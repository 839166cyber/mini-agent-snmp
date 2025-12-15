import json
import os
import asyncio
import time
import smtplib
from email.mime.text import MIMEText

# Librerías del Agente (Servidor)
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import context, cmdrsp
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c

# Librerías para enviar la Trap (Cliente)
from pysnmp.hlapi.asyncio import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, OctetString, Integer32, TimeTicks, sendNotification
)

import psutil

# --- CONFIGURACIÓN DE CORREO ---
SENDER_EMAIL = '740540.practicas@gmail.com' 
SENDER_PASS = 'cixn afxg ttpw rjgq'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# --- CONSTANTES Y ESTADO ---
STATE_FILE = "mib_state.json"
AGENT_START = time.time()

# Estructura inicial del MIB (OIDS CAMBIADOS AQUI)
DEFAULT_MIB_STATE = {
    "base_oid": "1.3.6.1.3.28308.1",
    "scalars": {
        "manager": {
            "oid": "1.3.6.1.3.28308.1.1.0",
            "type": "DisplayString",
            "access": "read-write",
            "value": "NetAdmin",
            "min": 1,
            "max": 64
        },
        "managerEmail": {
            "oid": "1.3.6.1.3.28308.1.2.0",
            "type": "DisplayString",
            "access": "read-write",
            "value": "740540@unizar.es",
            "min": 3,
            "max": 128
        },
       
        "cpuUsage": {
            "oid": "1.3.6.1.3.28308.1.3.0",
            "type": "Integer32",
            "access": "read-only",
            "value": 0,
            "min": 0,
            "max": 100
        },
        
        "cpuThreshold": {
            "oid": "1.3.6.1.3.28308.1.4.0",
            "type": "Integer32",
            "access": "read-write",
            "value": 80,
            "min": 0,
            "max": 100
        }
    }
}

def sys_uptime_ticks() -> int:
    """Devuelve centésimas de segundo desde que arrancó el agente"""
    return int((time.time() - AGENT_START) * 100)

def load_or_init_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
            if "base_oid" in state and "scalars" in state:
                return state
        except Exception:
            print("Error al leer mib_state.json, regenerando...")
    else:
        print("Archivo no encontrado, creando mib_state.json con nuevos OIDs...")

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_MIB_STATE, f, indent=4)
    return DEFAULT_MIB_STATE

STATE = load_or_init_state()

oid_map = {}
for key, obj in STATE["scalars"].items():
    oid_tuple = tuple(int(x) for x in obj["oid"].split("."))
    oid_map[oid_tuple] = key


class JsonStore:
    def __init__(self, state, state_file):
        self.state = state
        self.state_file = state_file
        self.oid_map = {}
        for key, obj in self.state["scalars"].items():
            oid_tuple = tuple(int(x) for x in obj["oid"].split("."))
            self.oid_map[oid_tuple] = key

    def _get_scalar(self, oid_tuple):
        key = self.oid_map.get(oid_tuple)
        if not key:
            return None, None
        return key, self.state["scalars"][key]

    # store.get_exact
    def get_exact(self, oid_tuple):
        key, scalar = self._get_scalar(oid_tuple)
        if not scalar:
            return False, v2c.NoSuchObject()
        val = scalar["value"]
        if scalar["type"] == "DisplayString":
            return True, v2c.OctetString(str(val).encode("utf-8"))
        if scalar["type"] == "Integer32":
            return True, v2c.Integer(int(val))
        return False, v2c.NoSuchObject()

    # store.get_next
    def get_next(self, oid_tuple):
        sorted_oids = sorted(self.oid_map.keys())
        for oid in sorted_oids:
            if oid > oid_tuple:
                ok, val = self.get_exact(oid)
                return ok, oid, val
        return False, None, None

    # store.validate_set
    def validate_set(self, oid_tuple, snmp_val):
        """
        Return (errStatus, dummyIndex)

        Codes:
          0  = noError
          6  = noAccess
          7  = wrongType
          10 = wrongValue
          17 = notWritable
        """
        key, scalar = self._get_scalar(oid_tuple)
        if not scalar:
            return 6, 0  # noAccess: unknown OID

        if scalar["access"] != "read-write":
            return 17, 0  # notWritable

        obj_type = scalar["type"]

        if obj_type == "DisplayString":
            if not isinstance(snmp_val, OctetString):
                return 7, 0  # wrongType
            s = bytes(snmp_val).decode('utf-8', 'ignore')
            min_len = scalar.get("min", 0)
            max_len = scalar.get("max", 65535)
            if not (min_len <= len(s) <= max_len):
                return 10, 0  # wrongValue
            return 0, 0  # ok

        if obj_type == "Integer32":
            if not isinstance(snmp_val, Integer32):
                return 7, 0  # wrongType
            try:
                i = int(snmp_val)
            except Exception:
                return 10, 0
            min_v = scalar.get("min", -2147483648)
            max_v = scalar.get("max", 2147483647)
            if not (min_v <= i <= max_v):
                return 10, 0  # wrongValue
            return 0, 0  # ok

        return 7, 0  # unknown type -> wrongType

    def commit_set(self, oid_tuple, snmp_val):
        key, scalar = self._get_scalar(oid_tuple)
        if not scalar:
            return False
        if scalar["type"] == "Integer32":
            new_value = int(snmp_val)
        elif scalar["type"] == "DisplayString":
            new_value = str(snmp_val)
        else:
            new_value = snmp_val.prettyPrint()
        self.state["scalars"][key]["value"] = new_value
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=4)
        print(f"[SET] Guardando {key} -> {new_value}")
        return True

store = JsonStore(STATE, STATE_FILE)


class JsonGet(cmdrsp.GetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            found, value = store.get_exact(tuple(oid))
            rsp.append((oid, value if found else v2c.NoSuchObject()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0); v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


class JsonGetNext(cmdrsp.NextCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            ok, next_oid, val = store.get_next(tuple(oid))
            if ok:
                rsp.append((v2c.ObjectIdentifier(next_oid), val))
            else:
                rsp.append((oid, v2c.EndOfMibView()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0); v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


class JsonSet(cmdrsp.SetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        print(f"JsonSet ejecutado")

        # Phase 1: validate
        for idx, (oid, val) in enumerate(req, start=1):
            errStatus, _ = store.validate_set(tuple(oid), val)
            if errStatus != 0:
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setErrorIndex(rspPDU, idx)
                v2c.apiPDU.setVarBinds(rspPDU, req)  # echo original
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return

        # Phase 2: commit
        for oid, val in req:
            store.commit_set(tuple(oid), val)

        # Reply with post-SET values
        rsp = []
        for oid, _ in req:
            found, value = store.get_exact(tuple(oid))
            rsp.append((oid, value if found else v2c.NoSuchObject()))

        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

# --- FUNCIÓN 1: ENVÍO DE EMAIL HTML (Con Hora del Evento) ---

def send_email_alert_sync(cpu_val, threshold, target_email):
    # 1. Capturamos la hora actual formateada (Hora:Minuto:Segundo Día/Mes/Año)
    event_time = time.strftime("%H:%M:%S %d/%m/%Y")
    
    subject = f"🚨 ALERTA: CPU al {cpu_val}% en Servidor Local"
    
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f6f8; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            
            <div style="background-color: #e74c3c; padding: 20px; text-align: center; color: white;">
                <h1 style="margin: 0; font-size: 24px;">⚠️ Umbral de CPU Superado</h1>
            </div>
            
            <div style="padding: 30px;">
                <p style="color: #555;">El agente SNMP ha detectado una carga crítica en el sistema.</p>
                
                <div style="background-color: #fcebeb; border-left: 5px solid #e74c3c; padding: 15px; margin: 20px 0;">
                    <table style="width: 100%;">
                        <tr>
                            <td style="color:#555;">Uso Actual:</td>
                            <td style="text-align:right; color:#c0392b; font-weight:bold; font-size:20px;">{cpu_val}%</td>
                        </tr>
                        <tr>
                            <td style="color:#555;">Umbral Configurado:</td>
                            <td style="text-align:right; font-weight:bold;">{threshold}%</td>
                        </tr>
                        <tr>
                            <td style="color:#555; padding-top: 5px;">Hora del evento:</td>
                            <td style="text-align:right; color:#555; font-size: 14px; padding-top: 5px;">{event_time}</td>
                        </tr>
                    </table>
                </div>
                
                <p style="font-size: 12px; color: #999; text-align: center;">Generado por Python SNMP Agent</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    msg = MIMEText(html_content, "html")
    msg["From"] = SENDER_EMAIL
    msg["To"] = target_email
    msg["Subject"] = subject

    try:
        print(f"📧 Conectando a Gmail para enviar alerta a {target_email}...")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASS)
            server.send_message(msg)
        print(f"✅ Email enviado correctamente (Hora: {event_time}).")
    except Exception as e:
        print(f"❌ Error al enviar email: {e}")

# --- FUNCIÓN 2: ENVÍO DE SNMP TRAP (ACTUALIZADA CON NUEVOS OIDs) ---

async def send_snmp_trap(cpu_val, threshold, target_email):
    """
    Envía una notificación TRAP al puerto 162.
    """
    print(f"📡 Enviando SNMP TRAP a 127.0.0.1:162...")

    from pysnmp.hlapi.asyncio import NotificationType

    trap_engine = SnmpEngine()
    
    # 1. Definimos el destino
    transport_target = await UdpTransportTarget.create(('127.0.0.1', 162))

    # 2. Construimos la Trap
    trap_oid = "1.3.6.1.3.28308.2.1"
    
    trap_object = NotificationType(ObjectIdentity(trap_oid))
    trap_object.addVarBinds(
        # CAMBIO: Actualizados los OIDs para coincidir con el nuevo MIB
        ('1.3.6.1.3.28308.1.3.0', Integer32(int(cpu_val))),     # cpuUsage es 1.3.0
        ('1.3.6.1.3.28308.1.4.0', Integer32(int(threshold))),   # cpuThreshold es 1.4.0
        ('1.3.6.1.3.28308.1.2.0', OctetString(str(target_email))) # managerEmail
    )

    # 3. Enviamos
    errorIndication, errorStatus, errorIndex, varBinds = await sendNotification(
        trap_engine,
        CommunityData('public', mpModel=1), # SNMPv2c
        transport_target,
        ContextData(),
        'trap',
        trap_object 
    )

    if errorIndication:
        print(f"❌ Error enviando Trap: {errorIndication}")
    else:
        print(f"✅ SNMP TRAP enviada exitosamente.")

# --- TAREA DE MONITORIZACIÓN ---

async def cpu_sampler():
    print("[Monitor] Iniciando sampler de CPU...")
    psutil.cpu_percent(interval=None)  # warm-up
    
    last_over = False
    loop = asyncio.get_running_loop()

    while True:
        await asyncio.sleep(5)

        # 1) Leer CPU
        cpu = round(psutil.cpu_percent(interval=None))
        cpu = max(0, min(100, cpu))

        # 2) Actualizar estado en memoria
        STATE["scalars"]["cpuUsage"]["value"] = cpu
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(STATE, f, indent=4)

        # 3) Verificar Umbrales
        try:
            thr = int(STATE["scalars"]["cpuThreshold"]["value"])
            target_email = STATE["scalars"]["managerEmail"]["value"]

            over = cpu > thr
            if over and not last_over:
                print(f"\n[ALERTA] CPU {cpu}% > {thr}%. Disparando notificaciones...")

                # A. Enviar Email (en hilo)
                loop.run_in_executor(None, send_email_alert_sync, cpu, thr, target_email)

                # B. Enviar Trap (async)
                #await send_snmp_trap(cpu, thr, target_email)

            last_over = over

        except Exception as e:
            print(f"Error en lógica de monitorización: {e}")


# --- MAIN ---

def main():
    snmpEngine = engine.SnmpEngine()
    snmpContext = context.SnmpContext(snmpEngine)
    
    config.addTransport(snmpEngine, udp.DOMAIN_NAME, udp.UdpTransport().openServerMode(('127.0.0.1', 16100)))
    
    config.addV1System(snmpEngine, 'public-area', 'public')
    config.addV1System(snmpEngine, 'private-area', 'private')
    
    for secModel in (1, 2):
        config.addVacmUser(snmpEngine, secModel, 'public-area', 'noAuthNoPriv', readSubTree=(1, 3, 6, 1))
        config.addVacmUser(snmpEngine, secModel, 'private-area', 'noAuthNoPriv', readSubTree=(1, 3, 6, 1), writeSubTree=(1, 3, 6, 1))

    JsonGet(snmpEngine, snmpContext)
    JsonSet(snmpEngine, snmpContext)
    JsonGetNext(snmpEngine, snmpContext)
    
    loop = asyncio.get_event_loop()
    loop.create_task(cpu_sampler()) 
    
    print("-------------------------------------------------------")
    print("🤖 Agente SNMP v2c (OIDs Actualizados)")
    print("📍 Escuchando consultas en: 127.0.0.1:16100")
    print("📍 Destino de Traps:        127.0.0.1:162")
    print("-------------------------------------------------------")
    
    try:
        loop.run_forever()
    finally:
        loop.stop()

if __name__ == "__main__":
    main()