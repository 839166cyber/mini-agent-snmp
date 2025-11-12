import json
from pysnmp.entity.engine import SnmpEngine
from pysnmp.entity import config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.proto.rfc1902 import NoSuchObject, EndOfMibView, OctetString, Integer
from pysnmp.proto.api import v2c
from pysnmp.proto.agent import cmdrsp
import asyncio, psutil, time, smtplib
from email.mime.text import MIMEText
from pysnmp.hlapi.asyncio import *

# --- Configuración SNMP Engine ---
snmpEngine = SnmpEngine()

config.addV1System(snmpEngine, 'ro-user', 'public')
config.addV1System(snmpEngine, 'rw-user', 'private')
config.addVacmUser(snmpEngine, 2, 'ro-user', 'noAuthNoPriv', (1,3,6,1), (), ())
config.addVacmUser(snmpEngine, 2, 'rw-user', 'noAuthNoPriv', (1,3,6,1), (1,3,6,1), ())

# --- Carga JSON store ---
with open('mib_state.json', 'r') as f:
    json_data = json.load(f)
scalars = {}
for name, props in json_data['scalars'].items():
    props['oid'] = tuple(int(x) for x in props['oid'].split('.'))
    scalars[name] = props
sorted_oids = sorted([props['oid'] for props in scalars.values()])

def py_to_snmp_type(value, type_snmp):
    if type_snmp == "DisplayString":
        return OctetString(value.encode('utf-8'))
    if type_snmp == "Integer32":
        return Integer(int(value))
    return value

def oid_tuple_to_scalar(oid_tuple):
    for obj, info in scalars.items():
        if info["oid"] == oid_tuple:
            return obj
    return None

class Store:
    def get_exact(self, oid_tuple):
        obj = oid_tuple_to_scalar(oid_tuple)
        if obj in scalars:
            value_py = scalars[obj]['value']
            type_snmp = scalars[obj]['type']
            value_snmp = py_to_snmp_type(value_py, type_snmp)
            return True, value_snmp
        else:
            return False, None

    def get_next(self, oid_tuple):
        for soid in sorted_oids:
            if soid > oid_tuple:
                obj = oid_tuple_to_scalar(soid)
                value_py = scalars[obj]['value']
                type_snmp = scalars[obj]['type']
                value_snmp = py_to_snmp_type(value_py, type_snmp)
                return True, soid, value_snmp
        return False, oid_tuple, None

    def validate_set(self, oid_tuple, val, community_name="public"):
        obj = oid_tuple_to_scalar(oid_tuple)
        if obj is None:
            return 6, 0  # noAccess
        access = scalars[obj]['access']
        if access != 'read-write':
            return 17, 0  # notWritable
        if community_name == "public":
            return 6, 0  # noAccess
        type_snmp = scalars[obj]['type']
        if type_snmp == "DisplayString":
            if not isinstance(val, OctetString):
                return 7, 0
            valdecoded = val.asOctets().decode('utf-8')
            if not (scalars[obj]['minlen'] <= len(valdecoded) <= scalars[obj]['maxlen']):
                return 10, 0
        if type_snmp == "Integer32":
            if not isinstance(val, Integer):
                return 7, 0
            intval = int(val)
            if not (scalars[obj]['min'] <= intval <= scalars[obj]['max']):
                return 10, 0
        return 0, 0

    def commit_set(self, oid_tuple, val):
        obj = oid_tuple_to_scalar(oid_tuple)
        type_snmp = scalars[obj]['type']
        if type_snmp == "DisplayString":
            scalars[obj]['value'] = val.asOctets().decode('utf-8')
        if type_snmp == "Integer32":
            scalars[obj]['value'] = int(val)
        # Guardar cambios al JSON
        out_json = {'baseoid': json_data['baseoid'], 'scalars': {}}
        for n, props in scalars.items():
            dic = {k: v for k,v in props.items()}
            dic['oid'] = '.'.join(str(x) for x in props['oid'])
            out_json['scalars'][n] = dic
        with open('mib_state.json', 'w') as f:
            json.dump(out_json, f, indent=2)

store = Store()

class JsonGet(cmdrsp.GetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=None):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            found, value = store.get_exact(tuple(oid))
            rsp.append((oid, value if found else NoSuchObject()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

class JsonGetNext(cmdrsp.NextCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=None):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            ok, next_oid, val = store.get_next(tuple(oid))
            if ok:
                rsp.append((v2c.ObjectIdentifier(next_oid), val))
            else:
                rsp.append((oid, EndOfMibView()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

class JsonSet(cmdrsp.SetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=None):
        community = acInfo.get("communityName") if acInfo and "communityName" in acInfo else "public"
        req = v2c.apiPDU.getVarBinds(PDU)
        for idx, (oid, val) in enumerate(req, start=1):
            errStatus, errIndex = store.validate_set(tuple(oid), val, community)
            if errStatus != 0:
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setErrorIndex(rspPDU, idx)
                v2c.apiPDU.setVarBinds(rspPDU, req)
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return
        for oid, val in req:
            store.commit_set(tuple(oid), val)
        rsp = []
        for oid, _ in req:
            found, value = store.get_exact(tuple(oid))
            rsp.append((oid, value if found else NoSuchObject()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

# --- Configuración EMAIL ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "icemanlabel@gmail.com"
SENDER_PASS = "kjjn qwac wxqf fbog"

def send_email_alert(cpu, threshold, to_addr):
    subject = f"🚨 Alerta CPU: {cpu}% supera umbral ({threshold}%)"
    body = f"El agente SNMP detectó CPU={cpu}%, threshold={threshold}%."
    msg = MIMEText(body)
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_addr
    msg["Subject"] = subject

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASS)
            server.send_message(msg)
        print(f"📧 Email enviado a {to_addr}")
    except Exception as e:
        print(f"❌ Error email: {e}")

async def send_trap(snmpEngine, cpu, threshold, manager, managerEmail):
    errorIndication = await sendNotification(
        snmpEngine,
        CommunityData('private'),
        UdpTransportTarget(('127.0.0.1', 162)),
        ContextData(),
        'trap',
        [
            # Modifica la OID de notificación si es diferente en tu MIB
            ObjectType(ObjectIdentity('1.3.6.1.4.1.28308.1.2.0.1')),
            ObjectType(ObjectIdentity('1.3.6.1.4.1.28308.1.1.3.0'), Integer(cpu)),   # cpuUsage
            ObjectType(ObjectIdentity('1.3.6.1.4.1.28308.1.1.4.0'), Integer(threshold)), # cpuThreshold
            ObjectType(ObjectIdentity('1.3.6.1.4.1.28308.1.1.1.0'), OctetString(manager)),
            ObjectType(ObjectIdentity('1.3.6.1.4.1.28308.1.1.2.0'), OctetString(managerEmail))
        ]
    )
    if errorIndication:
        print(f"❌ Error enviando trap: {errorIndication}")
    else:
        print(f"🚨 Trap SNMP enviada (CPU={cpu}, Threshold={threshold})")

async def cpusampler(store, snmpEngine):
    psutil.cpu_percent(interval=None)
    lastover = False
    while True:
        await asyncio.sleep(5)
        cpu = round(psutil.cpu_percent(interval=None))
        cpu = max(0, min(100, cpu))
        store.commit_set(scalars['cpuUsage']['oid'], Integer(cpu))
        threshold = int(scalars['cpuThreshold']['value'])
        manager = scalars['manager']['value']
        managerEmail = scalars['managerEmail']['value']

        over = cpu > threshold
        if over and not lastover:
            await send_trap(snmpEngine, cpu, threshold, manager, managerEmail)
            send_email_alert(cpu, threshold, managerEmail)
        lastover = over

def main():
    print("✅ Mini SNMP Agent está listo y cargado con mib_state.json")
    loop = asyncio.get_event_loop()
    loop.create_task(cpusampler(store, snmpEngine))
    loop.run_forever()

if __name__ == "__main__":
    main()
