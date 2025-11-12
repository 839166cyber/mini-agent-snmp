# mini_agent.py
# Main entrypoint for the mini SNMP agent
from pysnmp.proto.rfc1902 import NoSuchObject
from pysnmp.proto.api import v2c
from pysnmp.proto.agent import cmdrsp

class JsonGet(cmdrsp.GetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=None):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            found, value = store.get_exact(tuple(oid))
            if found:
                # value ya debe estar convertido a tipo SNMP (ej. OctetString o Integer)
                rsp.append((oid, value))
            else:
                rsp.append((oid, NoSuchObject()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

# Ejemplo esqueleto para store.get_exact (a adaptar con tu JSON)

def get_exact(oid_tuple):
    obj = oid_tuple_to_scalar(oid_tuple)  # tu función para traducir OID → nombre escalar
    if obj in scalars:
        value_py = scalars[obj]['value']
        type_snmp = scalars[obj]['type']
        value_snmp = py_to_snmp_type(value_py, type_snmp)  # tu helper para el tipo
        return True, value_snmp
    else:
        return False, None
from pysnmp.proto.api import v2c
from pysnmp.proto.agent import cmdrsp


class JsonGetNext(cmdrsp.NextCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=None):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            ok, next_oid, val = store.get_next(tuple(oid))
            if ok:
                rsp.append((v2c.ObjectIdentifier(next_oid), val))
            else:
                rsp.append((oid, v2c.EndOfMibView()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

from pysnmp.proto.api import v2c
from pysnmp.proto.agent import cmdrsp
from pysnmp.proto.rfc1905 import notWritable, wrongType, wrongLength, wrongValue, noCreation, inconsistentValue

class JsonSet(cmdrsp.SetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=None):
        req = v2c.apiPDU.getVarBinds(PDU)
        
        # Phase 1: validate
        for idx, (oid, val) in enumerate(req, start=1):
            # Validación personalizada: acceso, tipo, rango, longitudes
            errStatus, errIndex = store.validate_set(tuple(oid), val)
            # errStatus debe ser 0 si todo es OK
            # notWritable/wrongType/wrongValue/...
            if errStatus != 0:
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setErrorIndex(rspPDU, idx)
                v2c.apiPDU.setVarBinds(rspPDU, req) # Echo original
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return

        # Phase 2: commit (persist to JSON)
        for oid, val in req:
            # Guardar los valores validados
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



def main():
    print("✅ Mini SNMP Agent is running!")

if __name__ == "__main__":
    main()
