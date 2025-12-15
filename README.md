# Mini-SNMP Agent v2c 🚀

**Agente SNMP completo** para monitorización CPU con **GET/GETNEXT/SET**, persistencia JSON, **VACM**, emails HTML y **TRAPs v2c**. Proyecto académico **100% funcional**.

## ✨ Características principales

| OID | Nombre | Tipo | Acceso | Rango/Validación |
|-----|--------|------|--------|------------------|
| `1.3.6.1.3.28308.1.1.0` | `manager` | DisplayString | **RW** | 1-64 chars |
| `1.3.6.1.3.28308.1.2.0` | `managerEmail` | DisplayString | **RW** | 3-128 chars (email) |
| `1.3.6.1.3.28308.1.3.0` | `cpuUsage` | Integer32 | **RO** | 0-100% |
| `1.3.6.1.3.28308.1.4.0` | `cpuThreshold` | Integer32 | **RW** | 0-100% |

- ✅ **PySNMP v1arch/asyncio** (moderna, puerto 16100 sin root)
- ✅ **Monitor CPU** cada 5s → **Email + TRAP** si > threshold
- ✅ **Persistencia** `mib_state.json`
- ✅ **Control acceso**: `public`(RO) / `private`(RW)
- ✅ **Errores SNMPv2c**: noError(0), noAccess(6), wrongType(7), wrongValue(10), notWritable(17)
- ✅ **Cierre limpio** Ctrl+C

## 🚀 Instalación rápida

```bash
pip install pysnmp psutil
python mini_agente_copy.py
```

**Salida esperada**:
```
🤖 Agente SNMP v2c corriendo (Ctrl+C para parar)
📍 Escuchando: 127.0.0.1:16100
📍 Traps → 127.0.0.1:162
```

## 🧪 Pruebas completas

### 1. **Lectura** (comunidad `public`)
```bash
snmpget -v2c -c public 127.0.0.1:16100 1.3.6.1.3.28308.1.3.0
snmpwalk -v2c -c public 127.0.0.1:16100 1.3.6.1.3.28308.1
```

### 2. **Escritura** (comunidad `private`)
```bash
snmpset -v2c -c private 127.0.0.1:16100 1.3.6.1.3.28308.1.4.0 i 85
```

### 3. **Test automatizado**
```bash
python test.py
```

### 4. **Captura de traps**
```bash
sudo tcpdump -i lo udp port 162 -vv -X
```

## 🛡️ Control de Acceso VACM

| Comunidad | GET | GETNEXT | SET |
|-----------|-----|---------|-----|
| `public` | ✅ | ✅ | ❌ **noAccess(6)** |
| `private` | ✅ | ✅ | ✅ **(valida tipo/rango)** |

## 📧 Configuración Email
```python
SENDER_EMAIL = 'tu-email@gmail.com'
SENDER_PASS = 'tu-app-password-16chars'
```

## 🏗️ Arquitectura
```
main() → asyncio loop
├── SNMP Engine + VACM
├── Handlers: JsonGet/JsonGetNext/JsonSet
├── JsonStore (mib_state.json)
└── cpu_sampler() → {email,TRAP}
```

## 📁 Archivos
```
src/
├── mini_agente.py
├── test.py
└── mib_state.json (auto)
comandos.txt
README.md
```
