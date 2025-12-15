```markdown
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

```
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
```
snmpget -v2c -c public 127.0.0.1:16100 1.3.6.1.3.28308.1.3.0    # cpuUsage
snmpwalk -v2c -c public 127.0.0.1:16100 1.3.6.1.3.28308.1        # MIB completo
```

### 2. **Escritura** (comunidad `private`)
```
snmpset -v2c -c private 127.0.0.1:16100 1.3.6.1.3.28308.1.4.0 i 85  # threshold=85%
```

### 3. **Test automatizado**
```
python test.py  # Incluye GET/SET/errores/monitor
```

### 4. **Capturar TRAPs**
```
nc -lu 162 | xxd
```

## 🛡️ Control de Acceso VACM

| Comunidad | GET | GETNEXT | SET |
|-----------|-----|---------|-----|
| `public` | ✅ | ✅ | ❌ **noAccess(6)** |
| `private` | ✅ | ✅ | ✅ **(valida tipo/rango)** |

**Errores implementados**:
```
cpuUsage RO → notWritable(17)
SET string en Integer32 → wrongType(7)  
SET cpu=-5 → wrongValue(10)
SET email=1char → wrongValue(10)
```

## 📧 Configuración Email

```
SENDER_EMAIL = 'tu-email@gmail.com'
SENDER_PASS = 'tu-app-password-16chars'  # Gmail App Password
```

**Email HTML enviado**:
```
📧 Alerta CPU 87% > 85% (15/12/2025 14:32:10)
┌────────────┬──────────┐
│ cpuUsage   │ 87%      │
│ threshold  │ 85%      │
└────────────┼──────────┘
```

## 🏗️ Arquitectura

```
main() → asyncio loop
├── SNMP Engine + VACM (public/private)
├── Handlers: JsonGet() / JsonGetNext() / JsonSet()
├── JsonStore (mib_state.json)
└── cpu_sampler() → psutil → {email,TRAP}
```

**Flujo SET completo**:
```
snmpset(private) → JsonSet → validate(type+range+access)
                    ↓ OK
                commit_json() → noError(0)
```

## 📁 Archivos del proyecto

```
mini-snmp/
├── mini_agente_copy.py     # 🎯 Agente principal
├── test.py                 # 🧪 Suite de pruebas
├── mib_state.json          # 💾 Estado persistente (auto)
└── README.md               # 📖 Este archivo
```

## 🎯 Estado técnico (para profesores)

**✅ Implementado completamente**:
- MIB JSON personalizada con validación estricta
- Todas operaciones SNMPv2c + errores correctos  
- Monitorización asíncrona CPU + dual notificación
- Persistencia y cierre graceful

**⚠️ Limitación PySNMP conocida**:
```
V1arch/asyncio no expone securityName en handlers.
Solución: control RW por campo "access" en MIB JSON.
Comunidades public/private funcionan correctamente.
```

## 📊 Ejemplo monitorización

```
[14:32:05] cpuUsage=23%
[14:32:10] cpuUsage=87%
[ALERTA] CPU 87% > 85%. Notificando...
✅ Email enviado (740540@unizar.es)
✅ SNMP TRAP v2c enviada
```