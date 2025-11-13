"""
Mini SNMP Agent - Complete Version with Gmail Email Support
Compatible with PySNMP 4.4.12
Windows Compatible

IMPORTANT: Add your Gmail credentials in the "EMAIL CONFIGURATION" section below!
"""

import json
import os
import psutil
import asyncio
import smtplib
import time
from email.mime.text import MIMEText

# PySNMP imports
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp
from pysnmp.proto import api
from pysnmp.proto.rfc1902 import OctetString, Integer, ObjectIdentifier
from pysnmp.carrier.asyncio.dgram import udp

# SNMP Protocol module
v2c = api.protoModules[api.protoVersion2c]

# ═══════════════════════════════════════════════════════════════
# EMAIL CONFIGURATION - PUT YOUR GMAIL CREDENTIALS HERE!
# ═══════════════════════════════════════════════════════════════

# Option 1: Gmail with App Password (Recommended for testing)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587  # Use 587 for TLS

# ⚠️ CHANGE THESE VALUES ⚠️
SENDER_EMAIL = '740540.practicas@gmail.com'  # ← PUT YOUR GMAIL ADDRESS HERE
SENDER_PASS = 'hcpq sfgt dojo zwbx'     # ← PUT YOUR GMAIL APP PASSWORD HERE (16 chars)

# How to get Gmail App Password:
# 1. Go to https://myaccount.google.com/security
# 2. Enable 2-Step Verification if not already enabled
# 3. Go to "App passwords" section
# 4. Generate password for "Mail" application
# 5. Copy the 16-character password (format: xxxx xxxx xxxx xxxx)
# 6. Paste it above in SENDER_PASS

# ═══════════════════════════════════════════════════════════════

# Agent Configuration
STATE_FILE = 'mib_state.json'
OIDS_FILE = 'myagent_oids.json'
ENTERPRISE_OID = 28308  # Zaragoza Network Management Research Group

# Default OIDs
DEFAULT_OIDS = {
    "manager": {
        "oid": [1, 3, 6, 1, 4, 1, ENTERPRISE_OID, 1, 1, 1, 0],
        "type": "DisplayString",
        "access": "read-write",
        "min": 1,
        "max": 64
    },
    "managerEmail": {
        "oid": [1, 3, 6, 1, 4, 1, ENTERPRISE_OID, 1, 1, 2, 0],
        "type": "DisplayString",
        "access": "read-write",
        "min": 3,
        "max": 128
    },
    "cpuUsage": {
        "oid": [1, 3, 6, 1, 4, 1, ENTERPRISE_OID, 1, 1, 3, 0],
        "type": "Integer32",
        "access": "read-only",
        "min": 0,
        "max": 100
    },
    "cpuThreshold": {
        "oid": [1, 3, 6, 1, 4, 1, ENTERPRISE_OID, 1, 1, 4, 0],
        "type": "Integer32",
        "access": "read-write",
        "min": 0,
        "max": 100
    }
}

# Startup: Create JSON files if missing
def check_and_create_json(fname, default):
    if not os.path.exists(fname):
        with open(fname, 'w') as f:
            json.dump(default, f, indent=2)
        print(f"✅ Created {fname}")

default_state = {
    "manager": "Admin",
    "managerEmail": "admin@example.com",  # You can set default email here too
    "cpuUsage": 0,
    "cpuThreshold": 80
}

check_and_create_json(STATE_FILE, default_state)
check_and_create_json(OIDS_FILE, DEFAULT_OIDS)

# Load OIDs
def load_oids():
    with open(OIDS_FILE) as f:
        oids = json.load(f)
    name_map = {tuple(v["oid"]): k for k, v in oids.items()}
    oid_props = {k: v for k, v in oids.items()}
    sorted_oids = sorted([tuple(v["oid"]) for v in oids.values()])
    return name_map, oid_props, sorted_oids

NAME_MAP, OID_PROPS, SORTED_OIDS = load_oids()

# JsonStore class
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
            return 6, None
        
        name = NAME_MAP[oid_tuple]
        prop = OID_PROPS[name]
        
        if prop["access"] != "read-write":
            return 17, None
        
        if community_name == "public":
            return 17, None
        
        obj_type = prop["type"]
        
        if obj_type == "DisplayString" and not isinstance(snmp_val, OctetString):
            return 7, None
        if obj_type == "Integer32" and not isinstance(snmp_val, Integer):
            return 7, None
        
        if obj_type == "DisplayString":
            try:
                s = bytes(snmp_val).decode('utf-8', 'ignore')
                if not (prop["min"] <= len(s) <= prop["max"]):
                    return 10, None
            except:
                return 10, None
        
        if obj_type == "Integer32":
            try:
                i = int(snmp_val)
                if not (prop["min"] <= i <= prop["max"]):
                    return 10, None
            except:
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
    
    def _to_snmp_type(self, oid_tuple, value):
        name = NAME_MAP[oid_tuple]
        prop = OID_PROPS[name]
        
        if value is None or value == '':
            return OctetString('') if prop["type"] == "DisplayString" else Integer(0)
        
        if prop["type"] == "DisplayString":
            return OctetString(value)
        return Integer(value)

store = JsonStore(STATE_FILE)

# Command Responders
class JsonGet(cmdrsp.GetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=None):
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)
        rspVarBinds = []
        
        for oid, _ in reqVarBinds:
            found, value = store.get_exact(tuple(oid))
            rspVarBinds.append((oid, value if found else v2c.NoSuchObject()))
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rspVarBinds)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

class JsonGetNext(cmdrsp.NextCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=None):
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)
        rspVarBinds = []
        
        for oid, _ in reqVarBinds:
            ok, next_oid, val = store.get_next(tuple(oid))
            if ok:
                rspVarBinds.append((ObjectIdentifier(next_oid), val))
            else:
                rspVarBinds.append((oid, v2c.EndOfMibView()))
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rspVarBinds)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

class JsonSet(cmdrsp.SetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=None):
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)
        
        community = "public"
        if acInfo and hasattr(acInfo, 'get'):
            community = acInfo.get("communityName", "public")
        
        # Validate
        for idx, (oid, val) in enumerate(reqVarBinds, start=1):
            errStatus, _ = store.validate_set(tuple(oid), val, community)
            if errStatus != 0:
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setErrorIndex(rspPDU, idx)
                v2c.apiPDU.setVarBinds(rspPDU, reqVarBinds)
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return
        
        # Commit
        for oid, val in reqVarBinds:
            store.commit_set(tuple(oid), val)
        
        # Reply
        rspVarBinds = []
        for oid, _ in reqVarBinds:
            found, value = store.get_exact(tuple(oid))
            rspVarBinds.append((oid, value if found else v2c.NoSuchObject()))
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rspVarBinds)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

# Email notification function
def send_email_alert(cpu, threshold, to_addr):
    """Send email notification when CPU exceeds threshold using Gmail."""
    if not to_addr or '@' not in to_addr:
        print(f"⚠️  Invalid email address: {to_addr}")
        return
    
    # Check if Gmail credentials are configured
    if SENDER_EMAIL == 'your-email@gmail.com' or SENDER_PASS == 'xxxx xxxx xxxx xxxx':
        print(f"⚠️  Gmail credentials not configured! Email not sent.")
        print(f"    Edit the EMAIL CONFIGURATION section in the code.")
        return
    
    subject = f"🚨 CPU Alert: {cpu}% exceeds threshold ({threshold}%)"
    
    body = f"""CPU Usage Alert - SNMP Agent Notification

The SNMP agent has detected that CPU usage has exceeded the configured threshold.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ALERT DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Current CPU Usage: {cpu}%
Configured Threshold: {threshold}%

Manager: {store.data.get('manager', 'Unknown')}
Notification sent to: {to_addr}

Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Please check the system and take appropriate action if necessary.

This is an automated message from the Mini SNMP Agent.
"""
    
    msg = MIMEText(body)
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_addr
    msg["Subject"] = subject
    
    try:
        # Connect to Gmail SMTP server
        print(f"📧 Connecting to Gmail SMTP server...")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.ehlo()  # Identify ourselves to the server
            server.starttls()  # Secure the connection
            server.ehlo()  # Re-identify after TLS
            server.login(SENDER_EMAIL, SENDER_PASS)  # Login with App Password
            server.send_message(msg)
        
        print(f"✅ Email successfully sent to {to_addr}")
    
    except smtplib.SMTPAuthenticationError:
        print(f"❌ Gmail authentication failed!")
        print(f"   Check your App Password is correct (16 characters)")
        print(f"   Make sure 2-Step Verification is enabled")
    except smtplib.SMTPException as e:
        print(f"❌ SMTP error: {e}")
    except Exception as e:
        print(f"❌ Email error: {e}")

# SNMP Trap notification function  
def send_trap(cpu, threshold, manager, managerEmail):
    """Send SNMP v2c trap notification."""
    from pysnmp.entity.rfc3413.oneliner import ntforg
    
    try:
        ntfOrg = ntforg.NotificationOriginator()
        
        # Build trap varbinds
        varBinds = [
            # sysUpTime
            (ObjectIdentifier('1.3.6.1.2.1.1.3.0'), Integer(int(time.time() * 100))),
            # snmpTrapOID (your notification OID)
            (ObjectIdentifier('1.3.6.1.6.3.1.1.4.1.0'), 
             ObjectIdentifier(f'1.3.6.1.4.1.{ENTERPRISE_OID}.1.2.0.1')),
            # cpuUsage
            (ObjectIdentifier(f'1.3.6.1.4.1.{ENTERPRISE_OID}.1.1.3.0'), Integer(cpu)),
            # cpuThreshold
            (ObjectIdentifier(f'1.3.6.1.4.1.{ENTERPRISE_OID}.1.1.4.0'), Integer(threshold)),
            # manager
            (ObjectIdentifier(f'1.3.6.1.4.1.{ENTERPRISE_OID}.1.1.1.0'), OctetString(manager)),
            # managerEmail
            (ObjectIdentifier(f'1.3.6.1.4.1.{ENTERPRISE_OID}.1.1.2.0'), OctetString(managerEmail))
        ]
        
        # Send trap to localhost:162
        errorIndication, errorStatus, errorIndex, varBindReturn = ntfOrg.sendVarBinds(
            snmpEngine,
            'trap-target',
            None, '',  # contextEngineId, contextName
            varBinds
        )
        
        if errorIndication:
            print(f"❌ Trap error: {errorIndication}")
        else:
            print(f"🚨 SNMP trap sent successfully")
    
    except Exception as e:
        print(f"⚠️  Trap notification skipped: {e}")

# CPU Monitor with notifications
async def cpu_monitor():
    """Monitor CPU and send notifications when threshold exceeded."""
    
    # Warm up psutil
    psutil.cpu_percent(interval=None)
    last_over = False
    
    print("🔍 CPU monitoring started (checking every 5 seconds)")
    
    while True:
        await asyncio.sleep(5)
        
        # Get current CPU usage
        cpu = round(psutil.cpu_percent(interval=None))
        cpu = max(0, min(100, cpu))
        
        # Update cpuUsage (read-only, internal update)
        store.data["cpuUsage"] = cpu
        store.save()
        
        # Get threshold and manager info
        threshold = int(store.data.get("cpuThreshold", 80))
        manager = str(store.data.get("manager", "Admin"))
        managerEmail = str(store.data.get("managerEmail", "admin@example.com"))
        
        # Edge-triggered notification (only on transition from below to above)
        over = cpu > threshold
        if over and not last_over:
            print(f"\n{'='*60}")
            print(f"⚠️  CPU THRESHOLD EXCEEDED!")
            print(f"{'='*60}")
            print(f"   Current CPU: {cpu}%")
            print(f"   Threshold:   {threshold}%")
            print(f"   Manager:     {manager}")
            print(f"   Email:       {managerEmail}")
            print(f"{'='*60}\n")
            
            # Send SNMP trap
            send_trap(cpu, threshold, manager, managerEmail)
            
            # Send email notification
            send_email_alert(cpu, threshold, managerEmail)
            
            print(f"\n{'='*60}\n")
        
        last_over = over

# SNMP Engine Setup
snmpEngine = engine.SnmpEngine()

config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('127.0.0.1', 161))
)

# Configure trap destination
config.addTransport(
    snmpEngine,
    udp.domainName + (1,),
    udp.UdpTransport().openClientMode()
)

config.addV1System(snmpEngine, 'ro-user', 'public')
config.addV1System(snmpEngine, 'rw-user', 'private')
config.addV1System(snmpEngine, 'trap-community', 'public')

config.addVacmUser(
    snmpEngine, 2, 'ro-user', 'noAuthNoPriv',
    readSubTree=(1, 3, 6, 1),
    writeSubTree=(),
    notifySubTree=()
)
config.addVacmUser(
    snmpEngine, 2, 'rw-user', 'noAuthNoPriv',
    readSubTree=(1, 3, 6, 1),
    writeSubTree=(1, 3, 6, 1),
    notifySubTree=()
)

config.addTargetParams(
    snmpEngine,
    'trap-target',
    'trap-community',
    'noAuthNoPriv',
    1
)

config.addTargetAddr(
    snmpEngine,
    'trap-receiver',
    udp.domainName,
    ('127.0.0.1', 162),
    'trap-target',
    tagList='trap-tag'
)

config.addNotificationTarget(
    snmpEngine,
    'trap-target',
    'trap-tag',
    'trap'
)

JsonGet(snmpEngine)
JsonGetNext(snmpEngine)
JsonSet(snmpEngine)

# Main
async def main():
    print("\n" + "="*60)
    print("  Mini SNMP Agent with Email Notifications")
    print("="*60)
    print(f"  Enterprise OID: 1.3.6.1.4.1.{ENTERPRISE_OID}")
    print(f"  Listening on:   127.0.0.1:161")
    print(f"  Email via:      {SMTP_SERVER}")
    print("="*60 + "\n")
    
    if SENDER_EMAIL == 'your-email@gmail.com':
        print("⚠️  WARNING: Gmail credentials not configured!")
        print("   Edit EMAIL CONFIGURATION section to enable email alerts\n")
    
    asyncio.create_task(cpu_monitor())
    
    snmpEngine.transportDispatcher.jobStarted(1)
    
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except KeyboardInterrupt:
        print("\n\nShutting down agent...")
    finally:
        snmpEngine.transportDispatcher.closeDispatcher()

if __name__ == "__main__":
    asyncio.run(main())
