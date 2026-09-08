"""Live detection test harness for the CCDC EDR.

Generates BENIGN test artifacts that simulate implant/persistence traits from
the research guides, plants them, launches them, then polls the EDR API to
verify each expected detection fired. Cleans everything up afterwards.

Every artifact is inert: fake binaries are copies of cmd.exe with appended
strings (or byte blobs never executed), the "beacon" is a TCP loopback client,
the webshell is a text file of pattern strings. Nothing phones out.

Usage:  python tests/run_tests.py   (EDR must be running: python -m edr)
"""
import base64, json, os, re, socket, subprocess, sys, threading, time, urllib.request
import winreg

API = "http://127.0.0.1:8420"
TEMP = os.environ.get("TEMP", os.getcwd())
STARTUP = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")

def api(path, post=False):
    req = urllib.request.Request(API + path, method="POST" if post else "GET")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def wait_for(pred, timeout, step=2, desc=""):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = api("/api/state")
        if pred(s):
            return True, time.time() - t0
        time.sleep(step)
    return False, timeout

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + ("  -- " + detail if detail and not ok else ""))

# ---------------------------------------------------------------- artifacts

def make_fake_imix():
    """Copy of cmd.exe (still runs) with imix/Rust config strings appended as overlay."""
    p = os.path.join(TEMP, "sysupd_imix_test.exe")
    with open(r"C:\Windows\System32\cmd.exe", "rb") as f:
        data = f.read()
    overlay = (b"\x00" * 512 +
               b"IMIX_CALLBACK_URI=http://127.0.0.1:9443/tavern\x00"
               b"IMIX_SERVER_PUBKEY=AAABBBCCC\x00IMIX_BEACON_ID=test-01\x00"
               b"IMIX_GUARDRAILS=file:/ccdc\x00IMIX_CONFIG=transports\x00"
               b"main.eldritch\x00eldritch\x00tavern\x00"
               b"rust_begin_unwind\x00panicked at src/main.rs\x00TcpStream\x00chacha\x00/rustc/\x00")
    with open(p, "wb") as f:
        f.write(data + overlay)
    return p

def make_fake_musl_elf():
    p = os.path.join(TEMP, "updhelper_test.elf")
    with open(p, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200 +
                b"musl\x00IMIX_CALLBACK_URI\x00IMIX_BEACON_ID\x00eldritch\x00")
    return p

def make_tome():
    p = os.path.join(TEMP, "staging.eldritch")
    with open(p, "w") as f:
        f.write("# benign simulated eldritch tome\ndef install():\n  load_library(\"x\")\n"
                "reverse_shell(\"127.0.0.1\", 1)\n# reflective loader test\n")
    return p

def make_webshell():
    p = os.path.join(TEMP, "www", "health.php")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write("<?php // simulated webshell pattern (inert)\n eval($_POST['cmd']); ?>\n")
    return p

def make_startup_item():
    p = os.path.join(STARTUP, "ccdc-test-persistence.bat")
    with open(p, "w") as f:
        f.write("@echo rem CCDC EDR test persistence marker (inert)\n")
    return p

# ---------------------------------------------------------------- tests

def t_static_signatures():
    imix, elf, tome, shell = make_fake_imix(), make_fake_musl_elf(), make_tome(), make_webshell()
    api("/api/scan", post=True)
    ok1, d1 = wait_for(lambda s: any(a["rule"] == "SIG-REALM-IMIX" for a in s["alerts"]), 20, desc="imix")
    ok2, d2 = wait_for(lambda s: any(a["rule"] == "SIG-MUSL-ELF" for a in s["alerts"]), 10, desc="musl")
    ok3, d3 = wait_for(lambda s: any(a["rule"] == "SIG-ELDRITCH-TOME" for a in s["alerts"]), 10, desc="tome")
    ok4, d4 = wait_for(lambda s: any(a["rule"].startswith("SIG-WEBSHELL") for a in s["alerts"]), 10, desc="webshell")
    check("On-write signature scan: Realm imix binary", ok1)
    check("On-write signature scan: musl ELF", ok2)
    check("On-write signature scan: eldritch tome", ok3)
    check("On-write signature scan: webshell", ok4)
    return imix

def t_launch_detection(imix_path):
    """Launch the fake implant (kept alive ~12s so both WMI poll and 4688 see it)."""
    subprocess.Popen([imix_path, "/c", "ping -n 12 127.0.0.1 > nul"],
                     creationflags=subprocess.CREATE_NO_WINDOW)
    ok, d = wait_for(lambda s: any(a["rule"] in ("PROG-IMPLANT-LAUNCH", "EVT-4688-TEMP")
                                   for a in s["alerts"]), 40)
    check("Launch-time detection: implant image scanned at process start", ok)

def t_encoded_powershell():
    enc = base64.b64encode("Start-Sleep -Seconds 15; Write-Output 'ccdc benign test'".encode("utf-16-le")).decode()
    subprocess.Popen(["powershell", "-NoProfile", "-EncodedCommand", enc],
                     creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = wait_for(lambda s: any(a["rule"] == "PROC-ENC-PS" for a in s["alerts"]
                                   or a["rule"] == "EVT-4688-SUSP" for a in s["alerts"]), 40)
    check("Process rule: encoded PowerShell command line", ok)

def t_persistence_runkey():
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                       r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, "CCDCTestPayload", 0, winreg.REG_SZ, r"C:\Users\Public\sysupd.exe")
    winreg.CloseKey(k)
    ok, _ = wait_for(lambda s: any(a["rule"] == "PERS-RUNKEY" for a in s["alerts"]), 45)
    check("Persistence auditor: new autorun value", ok)

def t_persistence_startup():
    make_startup_item()
    ok, _ = wait_for(lambda s: any(a["rule"] == "PERS-STARTUP" for a in s["alerts"]), 45)
    check("Persistence auditor: startup-folder item", ok)

def t_persistence_task():
    subprocess.run(["schtasks", "/create", "/f", "/tn", "CCDCTestTask", "/sc", "minute",
                    "/mo", "60", "/tr", "cmd /c exit"], capture_output=True)
    ok, _ = wait_for(lambda s: any(a["rule"] == "PERS-TASK" for a in s["alerts"]
                                   or a["rule"] == "EVT-4698" for a in s["alerts"]), 45)
    check("Persistence auditor / eventlog: scheduled task created", ok)

def t_persistence_service():
    subprocess.run(["sc", "create", "CCDCTestSvc", "binPath=", r"C:\Windows\System32\cmd.exe"],
                   capture_output=True)
    ok, _ = wait_for(lambda s: any(a["rule"] in ("PERS-SERVICE", "EVT-7045") for a in s["alerts"]), 45)
    check("Persistence auditor / eventlog: new service (7045)", ok)

def t_beacon():
    """Loopback TCP beacon: connect every 5s (+/- jitter) for ~50s, hold 2s."""
    stop = threading.Event()
    def server():
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 9443)); srv.listen(5); srv.settimeout(1)
        while not stop.is_set():
            try: srv.accept()[0].close()
            except socket.timeout: pass
        srv.close()
    th = threading.Thread(target=server, daemon=True); th.start()
    def client():
        while not stop.is_set():
            try:
                c = socket.create_connection(("127.0.0.1", 9443), timeout=2); time.sleep(2); c.close()
            except OSError:
                pass
            time.sleep(3 + (0.5 if int(time.time()) % 2 else -0.5))
    th2 = threading.Thread(target=client, daemon=True); th2.start()
    ok, d = wait_for(lambda s: any(a["rule"] == "NET-BEACON" for a in s["alerts"]), 90, step=3)
    check("Beacon cadence: periodic loopback callback flagged", ok, f"waited {d:.0f}s")
    stop.set()

# ---------------------------------------------------------------- cleanup

def cleanup():
    for f in [os.path.join(TEMP, "sysupd_imix_test.exe"), os.path.join(TEMP, "updhelper_test.elf"),
              os.path.join(TEMP, "staging.eldritch"), os.path.join(TEMP, "www", "health.php"),
              os.path.join(STARTUP, "ccdc-test-persistence.bat")]:
        try: os.remove(f)
        except OSError: pass
    try: os.rmdir(os.path.join(TEMP, "www"))
    except OSError: pass
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run",
                           0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(k, "CCDCTestPayload"); winreg.CloseKey(k)
    except OSError: pass
    subprocess.run(["schtasks", "/delete", "/f", "/tn", "CCDCTestTask"], capture_output=True)
    subprocess.run(["sc", "delete", "CCDCTestSvc"], capture_output=True)
    print("\n[*] cleanup done (registry key, task, service, files removed)")

def main():
    print("[*] verifying EDR is up...")
    try:
        s = api("/api/state")
    except Exception as e:
        print("EDR not reachable at", API, "-", e); sys.exit(2)
    print("[*] kernel/ETW source:", s["stats"].get("kernel_trace"))
    print("[*] test cycle beginning; benign artifacts only\n")
    try:
        imix = t_static_signatures()
        t_launch_detection(imix)
        t_encoded_powershell()
        t_persistence_runkey()
        t_persistence_startup()
        t_persistence_task()
        t_persistence_service()
        t_beacon()
    finally:
        cleanup()
    passed = sum(1 for _, ok, _ in results if ok)
    print("\n=== RESULTS: %d/%d passed ===" % (passed, len(results)))
    for name, ok, detail in results:
        print(("  PASS " if ok else "  FAIL ") + name + ("  -- " + detail if detail and not ok else ""))
    sys.exit(0 if passed == len(results) else 1)

if __name__ == "__main__":
    main()
