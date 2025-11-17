# Mini SNMP Agent

Agente SNMP completo desarrollado en Python 3.13 que implementa monitorización de CPU, gestión de objetos personalizados y notificaciones por email y traps SNMP.

## Resumen

Este proyecto implementa un agente SNMP v1/v2c totalmente funcional que expone cuatro objetos gestionados personalizados bajo el árbol enterprise OID `1.3.6.1.4.1.28308.1`. El agente incluye monitorización asíncrona de CPU, persistencia de estado en JSON, control de acceso mediante VACM (read-only/read-write según comunidad), y notificaciones automáticas cuando el uso de CPU supera un umbral configurable.

## Características

- **Soporte SNMP v1 y v2c** con operaciones GET, GETNEXT y SET
- **Cuatro objetos gestionados** (scalares):
  - `manager` (DisplayString, RW): Nombre del administrador
  - `managerEmail` (DisplayString, RW): Email del administrador
  - `cpuUsage` (Integer32, RO): Uso actual de CPU (0-100%)
  - `cpuThreshold` (Integer32, RW): Umbral de CPU para alertas (0-100%)
- **Monitorización asíncrona de CPU** cada 5 segundos con psutil
- **Persistencia de estado** en archivo JSON (`mib_state.json`)
- **Control de acceso VACM**:
  - Comunidad `public`: solo lectura (RO)
  - Comunidad `private`: lectura y escritura (RW)
- **Notificaciones duales** cuando CPU > threshold:
  - Email vía Gmail SMTP
  - SNMP Trap v2c (preparado para configuración)
- **MIB personalizada** (MYAGENT-MIB) compatible con Net-SNMP
- **Arquitectura modular** con handlers personalizados y backend JSON desacoplado

## Requisitos

### Software
- **Python 3.11+** (probado en Python 3.13)
- **PySNMP 7.1.22** o superior
- **Dependencias Python:**
  - `pysnmp >= 7.1.22`
  - `psutil >= 5.9.0`
  - `pyasn1 >= 0.4.8`

### Sistema operativo
- **Windows**: Ejecutar como Administrador para usar puerto 161
- **Linux**: Ejecutar con `sudo` para puerto 161, o usar puerto > 1024
- **Net-SNMP tools** instalados para pruebas (`snmpget`, `snmpwalk`, `snmpset`)

### Red
- Puerto UDP 161 (estándar SNMP) o puerto personalizado (ej: 1161)
- Firewall configurado para permitir tráfico UDP en el puerto elegido

## Instalación

### 1. Clonar o descargar el proyecto
```bash
git clone https://github.com/839166cyber/mini-agent-snmp
cd mini-snmp-agent
```

### 2. Instalar dependencias Python

**Usando pip:**
```bash
pip install pysnmp==7.1.22 psutil
```
**Usando entorno virtual (recomendado):**
```bash
python -m venv venv
Windows

venv\Scripts\activate
Linux/Mac

source venv/bin/activate

pip install pysnmp==7.1.22 psutil
```

### 3. Configurar credenciales de email (opcional)

Edita `mini_agent_v4.py` y configura tus credenciales Gmail para notificaciones:
```bash
SENDER_EMAIL = 'tu_email@gmail.com'
SENDER_PASS = 'xxxx xxxx xxxx xxxx' # App Password de 16 caracteres
```
> **Nota:** Para generar un App Password en Gmail, habilita la verificación en dos pasos y ve a: Configuración → Seguridad → Contraseñas de aplicaciones.

### 4. Ajustar el puerto (opcional)

Si no puedes ejecutar como Administrador/root, cambia el puerto en el código:
```bash
port = 1161 # Puerto alto (no requiere privilegios)
```

## Uso

### Iniciar el agente

**Windows (puerto 161):**

Como Administrador
```bash
python mini_agent_v4.py
```
**Linux (puerto 161):**
```bash
sudo python3 mini_agent_v4.py
```


### Verificar que el agente está corriendo

Deberías ver:
```bash
✅ Created mib_state.json
✅ Created myagent_oids.json
SnmpEngine creado.
Contexto SNMP registrado.
Transporte UDP abierto en 127.0.0.1:161
VACM y comunidades listos.
JsonGet registrado.
JsonGetNext registrado.
JsonSet registrado.
🔍 CPU monitoring started (every 5s)
Dispatcher RUN...
```

## Comandos SNMP para pruebas

### GET - Consultar valores

**Consultar manager:**
```bash
snmpget -v2c -c public 127.0.0.1 1.3.6.1.4.1.28308.1.1.0
Respuesta: SNMPv2-SMI::enterprises.28308.1.1.0 = STRING: "Admin"
```

**Consultar email:**
```bash
snmpget -v2c -c public 127.0.0.1 1.3.6.1.4.1.28308.1.2.0
```

**Consultar uso de CPU:**
```bash
snmpget -v2c -c public 127.0.0.1 1.3.6.1.4.1.28308.1.3.0
Respuesta: SNMPv2-SMI::enterprises.28308.1.3.0 = INTEGER: 45
```

**Consultar umbral de CPU:**
```bash
snmpget -v2c -c public 127.0.0.1 1.3.6.1.4.1.28308.1.4.0
```

### GETNEXT / WALK - Recorrer el MIB

**Recorrer todos los objetos:**
```bash
snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.4.1.28308.1
```

**Salida esperada:**
```bash
SNMPv2-SMI::enterprises.28308.1.1.0 = STRING: "Admin"
SNMPv2-SMI::enterprises.28308.1.2.0 = STRING: "admin@example.com"
SNMPv2-SMI::enterprises.28308.1.3.0 = INTEGER: 42
SNMPv2-SMI::enterprises.28308.1.4.0 = INTEGER: 80
```

### SET - Modificar valores (requiere comunidad `private`)

**Cambiar nombre del administrador:**
```bash
snmpset -v2c -c private 127.0.0.1 1.3.6.1.4.1.28308.1.1.0 s "John Doe"
```

**Cambiar email:**
```bash
snmpset -v2c -c private 127.0.0.1 1.3.6.1.4.1.28308.1.2.0 s "john@example.com"
```

**Cambiar umbral de CPU:**
```bash
snmpset -v2c -c private 127.0.0.1 1.3.6.1.4.1.28308.1.4.0 i 90
```

**Intentar modificar cpuUsage (fallará, es RO):**
```bash
snmpset -v2c -c private 127.0.0.1 1.3.6.1.4.1.28308.1.3.0 i 50
Error: notWritable (no such name) - es read-only
```

### Usar puerto personalizado

Si configuraste el agente en puerto 1161, añade `:1161` a la dirección:
```bash
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.1.0
snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.4.0 i 70
```

## Estructura de archivos
```bash
mini-snmp-agent/
├── mini_agent_v4.py # Agente SNMP principal
├── MYAGENT-MIB.txt # Definición MIB en formato SMIv2
├── mib_state.json # Estado persistente (generado automáticamente)
├── myagent_oids.json # Definición de OIDs (generado automáticamente)
└── README.md # Este archivo
```

## Archivos JSON generados

### mib_state.json
Contiene los valores actuales de los objetos gestionados:
```bash
{
"manager": "Admin",
"managerEmail": "admin@example.com",
"cpuUsage": 45,
"cpuThreshold": 80
}

### myagent_oids.json
Define la estructura de objetos con tipos, acceso y restricciones:

{
"manager": {
"oid":,​
"type": "DisplayString",
"access": "read-write",
"min": 1,
"max": 64
},
...
}
```