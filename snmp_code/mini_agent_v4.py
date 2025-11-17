"""
Mini SNMP Agent - Python 3.13 + PySNMP 7.1.22

- Async CPU monitor (scheduled on PySNMP loop)
- GET/GETNEXT/SET via custom responders backed by JSON store
- Gmail SMTP email notification on threshold crossing
- SNMP Trap notification on threshold crossing
- No dependency on acInfo in handlers (compatible with 7.x)
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
# Agent uptime tracking
# =========================
AGENT_START = time.time()

def sys_uptime_ticks() -> int:
    """Devuelve el uptime del agente en TimeTicks (centésimas de segundo)"""
    return int((time.time() - AGENT_START) * 100)

# =========================
# Email (Gmail) configuration
# =========================
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
# Configure your email if you want alerts
SENDER_EMAIL = '740540.practicas@gmail.com'  # ← PUT YOUR GMAIL ADDRESS HERE
SENDER_PASS = 'hcpq sfgt dojo zwbx'  # 16-char App Password

# =========================
# Files and OIDs
# =========================
STATE_FILE = 'mib_state.json'
OIDS_FILE = 'myagent_oids.json'
ENTERPRISE_OID = 28308

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
    "cpuThreshold": 10
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
print("DEBUG NAME_MAP:", NAME_MAP) # Prints para comprobar que NAME_MAP no está vacío
print("DEBUG SORTED_OIDS:", SORTED_OIDS)

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
        if prop["type"] == "DisplayString":
            return OctetString("" if value is None else str(value))
        try:
            return Integer(0 if value is None else int(value))
        except Exception:
            return Integer(0)
        
    def get_exact(self, oid_tuple):
        print(f"DEBUG get_exact: buscando {oid_tuple}") # Prints para comprobar que la tupla obtenida es la correcta
        print(f"DEBUG NAME_MAP keys: {list(NAME_MAP.keys())}")
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
    
    def validate_set(self, oid_tuple, snmp_val, _community_unused='public'):
        # 6=noAccess, 7=wrongType, 10=wrongValue, 17=notWritable
        if oid_tuple not in NAME_MAP:
            return 6, None
        name = NAME_MAP[oid_tuple]
        prop = OID_PROPS[name]
        if prop["access"] != "read-write":
            return 17, None
        if prop["type"] == "DisplayString":
            if not isinstance(snmp_val, OctetString):
                return 7, None
            s = bytes(snmp_val).decode('utf-8', 'ignore')
            if not (prop["min"] <= len(s) <= prop["max"]):
                return 10, None
            return 0, None
        if prop["type"] == "Integer32":
            if not isinstance(snmp_val, Integer):
                return 7, None
            try:
                i = int(snmp_val)
            except Exception:
                return 10, None
            if not (prop["min"] <= i <= prop["max"]):
                return 10, None
            return 0, None
        return 7, None
    
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
    
    # New method for internal CPU update (bypasses RO restriction)
    def set_cpu_usage_internal(self, cpu_value):
        """Actualiza cpuUsage (RO) desde el monitor interno sin validar SET"""
        self.data["cpuUsage"] = int(cpu_value)
        self.save()

store = JsonStore(STATE_FILE)

# =========================
# Responders (7.x signatures) + debug prints
# =========================

class JsonGet(cmdrsp.GetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        print("\n=== JsonGet handler LLAMADO ===")
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)
        print(f"Número de varbinds recibidos: {len(reqVarBinds)}")
        
        rspVarBinds = []
        for oid, _ in reqVarBinds:
            oid_tuple = tuple(oid)
            print(f"OID recibido: {oid_tuple}")
            print(f"Tipo de OID: {type(oid)}")
            print(f"¿Existe en NAME_MAP? {oid_tuple in NAME_MAP}")
            
            found, value = store.get_exact(oid_tuple)
            print(f"get_exact resultado: found={found}, value={value}")
            
            rspVarBinds.append((oid, value if found else rfc1905.NoSuchObject()))
        
        rspPDU = v2c.apiPDU.getResponsePDU(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rspVarBinds)
        self.sendPdu(snmpEngine, stateReference, rspPDU)
        print("=== JsonGet respuesta enviada ===\n")

class JsonGetNext(cmdrsp.NextCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        print("JsonGetNext handler llamado")
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)
        rspVarBinds = []
        for oid, _ in reqVarBinds:
            print("SNMP GETNEXT desde:", tuple(oid))
            ok, next_oid, val = store.get_next(tuple(oid))
            if ok:
                rspVarBinds.append((ObjectIdentifier(next_oid), val))
            else:
                rspVarBinds.append((oid, rfc1905.EndOfMibView()))
        rspPDU = v2c.apiPDU.getResponsePDU(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rspVarBinds)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

class JsonSet(cmdrsp.SetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        print("JsonSet handler llamado")
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)

        # Deducir securityName (opcional) para RO/RW
        sec_name = None
        try:
            ctx_list = snmpEngine.observer.getExecutionContext('rfc3412.receiveMessage:request')
            if ctx_list:
                (_, _, _, securityName, _, _, _) = ctx_list[0]
                sec_name = str(securityName)
        except Exception:
            pass
        is_rw = (sec_name == 'private')
        print("SecurityName:", sec_name, "is_rw:", is_rw)

        # Phase 1: validate
        for idx, (oid, val) in enumerate(reqVarBinds, start=1):
            print("SNMP SET solicitando:", tuple(oid), "valor:", val.prettyPrint())
            errStatus = 0
            if not is_rw:
                errStatus = 6  # noAccess
            else:
                errStatus, _ = store.validate_set(tuple(oid), val, 'private')
            if errStatus != 0:
                print("SET denegado. errStatus:", errStatus, "errIndex:", idx)
                rspPDU = v2c.apiPDU.getResponsePDU(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setErrorIndex(rspPDU, idx)
                v2c.apiPDU.setVarBinds(rspPDU, reqVarBinds)
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return

        # Phase 2: commit
        for oid, val in reqVarBinds:
            store.commit_set(tuple(oid), val)

        # Respond with post-SET values
        rspVarBinds = []
        for oid, _ in reqVarBinds:
            found, value = store.get_exact(tuple(oid))
            rspVarBinds.append((oid, value if found else rfc1905.NoSuchObject()))

        rspPDU = v2c.apiPDU.getResponsePDU(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rspVarBinds)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

# =========================
# Email notification
# =========================
def send_email_alert(cpu, threshold, to_addr):
    if not to_addr or '@' not in to_addr:
        print(f"⚠️ Invalid email: {to_addr}")
        return
    if SENDER_EMAIL == 'your_email@gmail.com' or SENDER_PASS.startswith('xxxx'):
        print("⚠️ Gmail credentials not configured. Edit SENDER_EMAIL/SENDER_PASS.")
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
# SNMP Trap notification
# =========================
def send_trap_notification(snmpEngine, cpu, threshold, email):
    """Envía trap SNMPv2c cuando CPU supera threshold"""
    print(f"📤 Preparando trap: CPU {cpu}% > {threshold}%")
    
    # varBinds: sysUpTime.0, snmpTrapOID.0, cpuUsage, cpuThreshold, managerEmail
    varBinds = [
        (ObjectIdentifier('1.3.6.1.2.1.1.3.0'), rfc1902.TimeTicks(sys_uptime_ticks())),
        (ObjectIdentifier('1.3.6.1.6.3.1.1.4.1.0'), ObjectIdentifier('1.3.6.1.4.1.28308.2.0.1')),  # cpuOverThresholdNotification
        (ObjectIdentifier('1.3.6.1.4.1.28308.1.3.0'), Integer(cpu)),
        (ObjectIdentifier('1.3.6.1.4.1.28308.1.4.0'), Integer(threshold)),
        (ObjectIdentifier('1.3.6.1.4.1.28308.1.2.0'), OctetString(email))
    ]
    
    # TODO: Implementar envío real con pysnmp notificator API
    # Por ahora solo registramos el trap construido
    print(f"📤 Trap construido con {len(varBinds)} varBinds")
    for oid, val in varBinds:
        print(f"  {oid.prettyPrint()} = {val.prettyPrint()}")

# =========================
# Async CPU sampler (edge-triggered trap)
# =========================
async def cpu_sampler(store, trap_sender_func):
    """
    Periodic task:
    - every 5s: read CPU, clamp to [0,100], update RO scalar
    - if cpuUsage crosses above cpuThreshold -> send a trap (edge-triggered)
    """
    print("cpu_sampler: arrancando monitor de CPU")
    psutil.cpu_percent(interval=None)  # warm-up
    last_over = False
    print("🔍 CPU monitoring started (every 5s)")
    
    while True:
        await asyncio.sleep(5)
        cpu = round(psutil.cpu_percent(interval=None))
        cpu = max(0, min(100, cpu))
        
        # Update RO scalar via internal setter
        store.set_cpu_usage_internal(cpu)
        print(f"cpu_sampler: cpuUsage actualizado a {cpu}%")
        
        # Leer threshold y email desde el store
        thr = int(store.data.get("cpuThreshold", 80))
        email = str(store.data.get("managerEmail", "admin@example.com"))
        
        over = cpu > thr
        if over and not last_over:
            print(f"\n⚠️ CPU threshold exceeded: {cpu}% > {thr}%")
            # Enviar trap
            trap_sender_func(cpu, thr, email)
            # También enviar email si está configurado
            send_email_alert(cpu, thr, email)
        last_over = over

# =========================
# SNMP Engine + Context + Transport + VACM (with debug prints)
# =========================
print("Inicializando snmpEngine...")
snmpEngine = engine.SnmpEngine()
print("SnmpEngine creado.")

snmpContext = context.SnmpContext(snmpEngine)
print("Contexto SNMP registrado.")

host = '127.0.0.1'
port = 161  # Prefer high port in dev; 161 needs admin/root
print("Registrando transporte UDP...")
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode((host, port))
)
print(f"Transporte UDP abierto en {host}:{port}")

print("Registrando comunidades y VACM...")
# 1) Map communities -> securityName (deben coincidir para simplicidad)
config.addV1System(snmpEngine, 'public', 'public')   # securityName='public', community='public'
config.addV1System(snmpEngine, 'private', 'private') # securityName='private', community='private'

# 2) Grant views per (securityModel, securityName)
for secModel in (1, 2):  # 1 = v1, 2 = v2c
    # Read-only: everything under 1.3.6.1 (includes your MIB)
    config.addVacmUser(
        snmpEngine, secModel, 'public', 'noAuthNoPriv',
        readSubTree=(1, 3, 6, 1)
    )
    # Read-write: same read view, plus write permission
    config.addVacmUser(
        snmpEngine, secModel, 'private', 'noAuthNoPriv',
        readSubTree=(1, 3, 6, 1),
        writeSubTree=(1, 3, 6, 1)
    )
print("VACM y comunidades listos.")


print("Instanciando responders...")
JsonGet(snmpEngine, snmpContext)
print("JsonGet registrado.")
JsonGetNext(snmpEngine, snmpContext)
print("JsonGetNext registrado.")
JsonSet(snmpEngine, snmpContext)
print("JsonSet registrado.")

print("OIDs gestionados:")
for oid in SORTED_OIDS:
    print(oid)

# =========================
# Main using PySNMP's loop
# =========================
def main():
    print("\n" + "="*60)
    print(" Mini SNMP Agent - Python 3.13 + PySNMP 7.1.22")
    print("="*60)
    print(f" Enterprise OID: 1.3.6.1.4.1.{ENTERPRISE_OID}")
    print(f" Listening on: {host}:{port}")
    print(f" Email via: {SMTP_SERVER}")
    print(f" Agent started at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(AGENT_START))}")
    print("="*60 + "\n")

    # Trap sender function
    def trap_sender(cpu, thr, email):
        send_trap_notification(snmpEngine, cpu, thr, email)

    loop = snmpEngine.transport_dispatcher.loop
    print("Preparando event loop y tarea cpu_sampler...")
    loop.create_task(cpu_sampler(store, trap_sender))
    print("Tarea cpu_sampler lanzada.")
    snmpEngine.transport_dispatcher.job_started(1)
    try:
        print("Dispatcher RUN...")
        snmpEngine.transport_dispatcher.run_dispatcher()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        snmpEngine.transport_dispatcher.close_dispatcher()
        print("Dispatcher CLOSED.")

if __name__ == "__main__":
    main()
