import subprocess
import time

AGENT_IP = "127.0.0.1:16100"
COMMUNITY_RO = "public"
COMMUNITY_RW = "private"

BASE_OID   = "1.3.6.1.3.28308.1"
OID_MGR    = f"{BASE_OID}.1.0"
OID_EMAIL  = f"{BASE_OID}.2.0"
OID_CPU    = f"{BASE_OID}.3.0"
OID_THRESH = f"{BASE_OID}.4.0"

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"


def pause():
    input(f"{YELLOW}Pulsa ENTER para continuar...{RESET}")


def run(cmd):
    print(f"   Comando: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.stdout.strip():
        print("   OUT:", r.stdout.strip())
    if r.stderr.strip():
        print("   ERR:", r.stderr.strip())
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def ok(name):
    print(f"{GREEN}[PASS]{RESET} {name}")


def fail(name):
    print(f"{RED}[FAIL]{RESET} {name}")


def test_basic_get():
    print(f"\n{YELLOW}TEST 1: Basic GET{RESET}")

    cmd = ["snmpget", "-v", "2c", "-c", COMMUNITY_RO, AGENT_IP, OID_MGR]
    out, err, code = run(cmd)
    if code == 0 and ("STRING" in out or "OCTET STRING" in out):
        ok("GET manager")
    else:
        fail("GET manager")

    cmd = ["snmpget", "-v", "2c", "-c", COMMUNITY_RO, AGENT_IP, OID_CPU]
    out, err, code = run(cmd)
    if code == 0 and ("INTEGER" in out or "Gauge32" in out):
        ok("GET cpuUsage")
    else:
        fail("GET cpuUsage")

    unknown_oid = f"{BASE_OID}.99.0"
    cmd = ["snmpget", "-v", "2c", "-c", COMMUNITY_RO, AGENT_IP, unknown_oid]
    out, err, code = run(cmd)
    if code != 0 or "No Such Object" in out or "No Such Instance" in out:
        ok("GET unknown OID → NoSuchObject")
    else:
        fail("GET unknown OID")


def test_getnext():
    print(f"\n{YELLOW}TEST 2: GETNEXT (lexicographic){RESET}")
    start_oid = f"{BASE_OID}.0"
    current_oid = start_oid
    seq = []

    for _ in range(6):
        cmd = ["snmpgetnext", "-v", "2c", "-c", COMMUNITY_RO, AGENT_IP, current_oid]
        out, err, code = run(cmd)
        if code != 0:
            fail("GETNEXT sequence")
            return
        seq.append(out)
        try:
            current_oid = out.split("=")[0].split()[-1]
        except Exception:
            break

    if len(seq) >= 4 and BASE_OID in seq[0]:
        ok("GETNEXT walk de 4 scalars")
    else:
        fail("GETNEXT walk")


def test_set_write():
    print(f"\n{YELLOW}TEST 3: SET (write path){RESET}")

    # manager
    new_mgr = "Alice"
    cmd = ["snmpset", "-v", "2c", "-c", COMMUNITY_RW, AGENT_IP, OID_MGR, "s", new_mgr]
    out, err, code = run(cmd)
    if code != 0:
        fail("SET manager")
        return

    cmd = ["snmpget", "-v", "2c", "-c", COMMUNITY_RO, AGENT_IP, OID_MGR]
    out, err, code = run(cmd)
    if new_mgr in out:
        ok("SET manager verificado")
    else:
        fail("Verificación manager")

    # managerEmail
    new_mail = "alice@example.com"
    cmd = ["snmpset", "-v", "2c", "-c", COMMUNITY_RW, AGENT_IP, OID_EMAIL, "s", new_mail]
    out, err, code = run(cmd)
    if code != 0:
        fail("SET managerEmail")
        return

    cmd = ["snmpget", "-v", "2c", "-c", COMMUNITY_RO, AGENT_IP, OID_EMAIL]
    out, err, code = run(cmd)
    if new_mail in out:
        ok("SET managerEmail verificado")
    else:
        fail("Verificación managerEmail")

    # cpuThreshold
    cmd = ["snmpset", "-v", "2c", "-c", COMMUNITY_RW, AGENT_IP, OID_THRESH, "i", "75"]
    out, err, code = run(cmd)
    if code == 0:
        ok("SET cpuThreshold=75")
    else:
        fail("SET cpuThreshold")


def test_negative_sets():
    print(f"\n{YELLOW}TEST 4: Negative SETs (errors){RESET}")

    # A) Escribir en Read-Only (cpuUsage)
    cmd = ["snmpset", "-v", "2c", "-c", COMMUNITY_RW,
           AGENT_IP, OID_CPU, "i", "50"]
    out, err, code = run(cmd)
    if code != 0 and ("notWritable" in out or "notWritable" in err or "Reason" in err):
        ok("SET en read-only bloqueado (cpuUsage)")
    else:
        fail("SET en read-only (cpuUsage)")

    # B) Tipo incorrecto en cpuThreshold
    cmd = ["snmpset", "-v", "2c", "-c", COMMUNITY_RW,
           AGENT_IP, OID_THRESH, "s", "NO_SOY_NUMERO"]
    out, err, code = run(cmd)
    if code != 0 and ("wrongType" in out or "wrongType" in err or "Bad value" in err):
        ok("SET wrongType detectado (cpuThreshold)")
    else:
        fail("SET wrongType (cpuThreshold)")

    # C) Valor fuera de rango en cpuThreshold
    cmd = ["snmpset", "-v", "2c", "-c", COMMUNITY_RW,
           AGENT_IP, OID_THRESH, "i", "150"]
    out, err, code = run(cmd)
    if code != 0 and ("wrongValue" in out or "wrongValue" in err or "Bad value" in err):
        ok("SET wrongValue detectado (cpuThreshold>100)")
    else:
        fail("SET wrongValue (cpuThreshold>100)")


def test_alarm():
    print(f"\n{YELLOW}TEST 5: Alarm / TRAP{RESET}")

    # bajamos UMBRAL, no cpuUsage
    cmd = ["snmpset", "-v", "2c", "-c", COMMUNITY_RW,
           AGENT_IP, OID_THRESH, "i", "0"]
    out, err, code = run(cmd)

    print("   Esperando ~6s para que el sampler dispare...")
    time.sleep(6)
    ok("Trigger alarma (revisa email / sniffer)")

    cmd = ["snmpset", "-v", "2c", "-c", COMMUNITY_RW,
           AGENT_IP, OID_THRESH, "i", "75"]
    run(cmd)



def main():
    print("========================================")
    print("   TEST AUTOMÁTICO MINI-SNMP AGENT")
    print("========================================")

    test_basic_get()
    pause()
    test_getnext()
    pause()
    test_set_write()
    pause()
    test_negative_sets()
    pause()
    test_alarm()

    print("\n========================================")
    print("   FIN DE LOS TESTS")
    print("========================================")


if __name__ == "__main__":
    main()
