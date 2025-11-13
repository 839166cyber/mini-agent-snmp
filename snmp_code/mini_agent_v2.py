"""
Mini SNMP Agent - Python 3.13 + PySNMP 7.1.22
- Async CPU monitor (scheduled on PySNMP loop)
- GET/GETNEXT/SET via custom responders backed by JSON store
- Gmail SMTP email notification on threshold crossing
- New snake_case dispatcher API to avoid deprecation warnings
"""

import json
import os
import time
import psutil
import asyncio
import smtplib
from email.mime.text import MIMEText

# PySNMP 7.1.22
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto import rfc1902, rfc1905
from pysnmp.proto.api import v2c

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Types
OctetString = rfc1902.OctetString
Integer = rfc1902.Integer32
ObjectIdentifier = rfc1902.ObjectIdentifier

# =========================
# Email (Gmail) configuration
# =========================
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
# CHANGE THESE:
SENDER_EMAIL = '740540.practicas@gmail.com'  # ← PUT YOUR GMAIL ADDRESS HERE
SENDER_PASS = 'hcpq sfgt dojo zwbx'            # Gmail App Password (16 chars)

# =========================
# Files and OIDs
# =========================
STATE_FILE = 'mib_state.json'
OIDS_FILE = 'myagent_oids.json'
ENTERPRISE_OID = 28308  # Zaragoza Network Management Research Group

DEFAULT_OIDS = {
    "manager": {
        "oid": [1, 3, 6, 1, 4, 1, ENTERPRISE_OID, 1, 1, 0],
        "type": "DisplayString",
        "access": "read-write",
        "min": 1,
        "max": 64
    },
    "managerEmail": {
        "oid": [1, 3, 6, 1, 4, 1, ENTERPRISE_OID, 1, 2, 0],
        "type": "DisplayString",
        "access": "read-write",
        "min": 3,
        "max": 128
    },
    "cpuUsage": {
        "oid": [1, 3, 6, 1, 4, 1, ENTERPRISE_OID, 1, 3, 0],
        "type": "Integer32",
        "access": "read-only",
        "min": 0,
        "max": 100
    },
    "cpuThreshold": {
        "oid": [1, 3, 6, 1, 4, 1, ENTERPRISE_OID, 1, 4, 0],
        "type": "Integer32",
        "access": "read-write",
        "min": 0,
        "max": 100
    }
}

def check_and_create_json(fname, default):
    if not os.path.exists(fname):
        with open(fname, 'w') as f:
            json.dump(default, f, indent=2)
        print(f"✅ Created {fname}")

default_state = {
    "manager": "Admin",
    "managerEmail": "740540@unizar.es",
    "cpuUsage": 0,
    "cpuThreshold": 80
}
check_and_create_json(STATE_FILE, default_state)
check_and_create_json(OIDS_FILE, DEFAULT_OIDS)

def load_oids():
    with open(OIDS_FILE) as f:
        oids = json.load(f)
    name_map = {tuple(v["oid"]): k for k, v in oids.items()}
    oid_props = {k: v for k, v in oids.items()}
    sorted_oids = sorted([tuple(v["oid"]) for v in oids.values()])
    return name_map, oid_props, sorted_oids

NAME_MAP, OID_PROPS, SORTED_OIDS = load_oids()

class JsonStore:
    def __init__(self, fname):
        self.fname = fname
        self.load()
    def load(self):
        with open(self.fname) as f:
            self.data = json.load(f)
    def save(self):
        with open(self.fname, 'w') as f:
            json.dump(self.data, f, indent=2)

    def _to_snmp_type(self, oid_tuple, value):
        name = NAME_MAP[oid_tuple]
        prop = OID_PROPS[name]
        if value is None or value == '':
            return OctetString('') if prop["type"] == "DisplayString" else Integer(0)
        if prop["type"] == "DisplayString":
            return OctetString(value)
        return Integer(value)

    def get_exact(self, oid_tuple):
        if oid_tuple in NAME_MAP:
            name = NAME_MAP[oid_tuple]
            value = self.data.get(name)
            return True, self._to_snmp_type(oid_tuple, value)
        return False, None

    def get_next(self, oid_tuple):
        idx = 0
        while idx < len(SORTED_OIDS) and SORTED_OIDS[idx] <= oid_tuple:
            idx += 1
        if idx < len(SORTED_OIDS):
            next_oid = SORTED_OIDS[idx]
            found, val = self.get_exact(next_oid)
            return True, next_oid, val
        return False, None, None

    def validate_set(self, oid_tuple, snmp_val, community_name="public"):
        if oid_tuple not in NAME_MAP:
            return 6, None  # noAccess
        name = NAME_MAP[oid_tuple]
        prop = OID_PROPS[name]
        if prop["access"] != "read-write":
            return 17, None  # notWritable
        if community_name == "public":
            return 6, None  # noAccess

        t = prop["type"]
        if t == "DisplayString" and not isinstance(snmp_val, OctetString):
            return 7, None  # wrongType
        if t == "Integer32" and not isinstance(snmp_val, Integer):
            return 7, None

        if t == "DisplayString":
            try:
                s = bytes(snmp_val).decode('utf-8', 'ignore')
            except Exception:
                return 10, None
            if not (prop["min"] <= len(s) <= prop["max"]):
                return 10, None  # wrongValue
        if t == "Integer32":
            try:
                i = int(snmp_val)
            except Exception:
                return 10, None
            if not (prop["min"] <= i <= prop["max"]):
                return 10, None
        return 0, None

    def commit_set(self, oid_tuple, snmp_val):
        name = NAME_MAP.get(oid_tuple)
        if not name:
            return False
        prop = OID_PROPS[name]
        if prop["type"] == "DisplayString":
            self.data[name] = bytes(snmp_val).decode('utf-8', 'ignore')
        else:
            self.data[name] = int(snmp_val)
        self.save()
        return True

store = JsonStore(STATE_FILE)

# =========================
# Command Responders (PySNMP 7.x signatures)
# =========================
class JsonGet(cmdrsp.GetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo):
        print(f"DEBUG: GET request received for PDU: {PDU}")
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)
        rspVarBinds = []
        for oid, _ in reqVarBinds:
            found, value = store.get_exact(tuple(oid))
            if not found:
                value = rfc1905.noSuchObject
            rspVarBinds.append((oid, value))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rspVarBinds)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

class JsonGetNext(cmdrsp.NextCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo):
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)
        rspVarBinds = []
        for oid, _ in reqVarBinds:
            ok, next_oid, val = store.get_next(tuple(oid))
            if ok:
                rspVarBinds.append((ObjectIdentifier(next_oid), val))
            else:
                rspVarBinds.append((oid, rfc1905.endOfMibView))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rspVarBinds)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

class JsonSet(cmdrsp.SetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo):
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)
        community = "public"
        if acInfo and hasattr(acInfo, 'get'):
            community = acInfo.get("communityName", "public")

        # Phase 1: validate
        for idx, (oid, val) in enumerate(reqVarBinds, start=1):
            errStatus, _ = store.validate_set(tuple(oid), val, community)
            if errStatus != 0:
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setErrorIndex(rspPDU, idx)
                v2c.apiPDU.setVarBinds(rspPDU, reqVarBinds)  # echo original
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return

        # Phase 2: commit
        for oid, val in reqVarBinds:
            store.commit_set(tuple(oid), val)

        # Respond with post-SET values
        rspVarBinds = []
        for oid, _ in reqVarBinds:
            found, value = store.get_exact(tuple(oid))
            if not found:
                value = rfc1905.noSuchObject
            rspVarBinds.append((oid, value))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rspVarBinds)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

# =========================
# Email notification
# =========================
def send_email_alert(cpu, threshold, to_addr):
    if not to_addr or '@' not in to_addr:
        print(f"⚠️  Invalid email: {to_addr}")
        return
    if SENDER_EMAIL == 'your-email@gmail.com' or SENDER_PASS.startswith('xxxx'):
        print("⚠️  Gmail credentials not configured. Edit SENDER_EMAIL/SENDER_PASS.")
        return

    subject = f"🚨 CPU Alert: {cpu}% exceeds {threshold}%"
    body = f"""CPU Usage Alert - SNMP Agent

Current CPU Usage: {cpu}%
Configured Threshold: {threshold}%

Manager: {store.data.get('manager', 'Unknown')}
Email: {to_addr}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}

This is an automated notification.
"""
    msg = MIMEText(body)
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_addr
    msg["Subject"] = subject

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SENDER_EMAIL, SENDER_PASS)
            server.send_message(msg)
        print(f"✅ Email sent to {to_addr}")
    except smtplib.SMTPAuthenticationError:
        print("❌ Gmail authentication failed (check App Password & 2FA).")
    except Exception as e:
        print(f"❌ Email error: {e}")

# =========================
# Async CPU monitor (scheduled on PySNMP loop)
# =========================
async def cpu_monitor():
    psutil.cpu_percent(interval=None)  # warm-up
    last_over = False
    print("🔍 CPU monitoring started (every 5s)")
    while True:
        await asyncio.sleep(5)
        cpu = round(psutil.cpu_percent(interval=None))
        cpu = max(0, min(100, cpu))
        store.data["cpuUsage"] = cpu
        store.save()
        threshold = int(store.data.get("cpuThreshold", 80))
        manager = str(store.data.get("manager", "Admin"))
        managerEmail = str(store.data.get("managerEmail", "admin@example.com"))

        over = cpu > threshold
        if over and not last_over:
            print(f"\n⚠️  CPU threshold exceeded: {cpu}% > {threshold}%")
            send_email_alert(cpu, threshold, managerEmail)
        last_over = over

# =========================
# SNMP Engine + Context + Transport + VACM
# =========================
snmpEngine = engine.SnmpEngine()
snmpContext = context.SnmpContext(snmpEngine)

config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('127.0.0.1', 161))
)

config.addV1System(snmpEngine, 'ro-user', 'public')
config.addV1System(snmpEngine, 'rw-user', 'private')

config.addVacmUser(
    snmpEngine, 2, 'ro-user', 'noAuthNoPriv',
    readSubTree=(1, 3, 6, 1),
    writeSubTree=()
)
config.addVacmUser(
    snmpEngine, 2, 'rw-user', 'noAuthNoPriv',
    readSubTree=(1, 3, 6, 1),
    writeSubTree=(1, 3, 6, 1)
)

# Register responders
JsonGet(snmpEngine, snmpContext)
JsonGetNext(snmpEngine, snmpContext)
JsonSet(snmpEngine, snmpContext)
print("RESPONDERS REGISTERED")



# =========================
# Main using PySNMP’s loop
# =========================
def main():
    print("\n" + "="*60)
    print("  Mini SNMP Agent - Python 3.13 + PySNMP 7.1.22")
    print("="*60)
    print(f"  Enterprise OID: 1.3.6.1.4.1.{ENTERPRISE_OID}")
    print(f"  Listening on:   127.0.0.1:161")
    print(f"  Email via:      {SMTP_SERVER}")
    print("="*60 + "\n")
    if SENDER_EMAIL == 'your-email@gmail.com' or SENDER_PASS.startswith('xxxx'):
        print("⚠️  Gmail not configured. Edit SENDER_EMAIL / SENDER_PASS.\n")

    loop = snmpEngine.transport_dispatcher.loop
    loop.create_task(cpu_monitor())

    snmpEngine.transport_dispatcher.job_started(1)
    try:
        snmpEngine.transport_dispatcher.run_dispatcher()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        snmpEngine.transport_dispatcher.close_dispatcher()

if __name__ == "__main__":
    main()
