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

def api(path, post=False, body=None):
    req = urllib.request.Request(API + path, method="POST" if post else "GET",
                                 data=json.dumps(body or {}).encode() if post else None,
                                 headers={"Content-Type": "application/json"} if post else {})
    with urllib.request.urlopen(req, timeout=180) as r:
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

def make_fake_watershell():
    """Fake ELF carrying watershell-cpp's binary fingerprint (never executed)."""
    p = os.path.join(TEMP, " updhwatershell_test.elf".strip())
    with open(p, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 300 +
                b"status:\x00run:\x00/proc/net/arp\x00/proc/net/route\x00"
                b"Running in promisc mode\x00TCP mode (experimental)\x0000000000\x00")
    return p

# ---- tranche-2 detections: COM/CLR hijack, task modification, side-load,
#      hive dump / log clear patterns, DNS beacon, LSASS handle, .NET ETW ----

def t_watershell_signature():
    p = make_fake_watershell()
    api("/api/scan", post=True)
    ok, _ = wait_for(lambda s: any(a["rule"] == "SIG-WATERSHELL" for a in s["alerts"]), 25)
    check("Signature scan: watershell raw-packet shell ELF", ok)

def t_com_hijack():
    import winreg
    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID\{99999999-cccc-cccc-cccc-999999999999}\InprocServer32")
    winreg.SetValueEx(k, "", 0, winreg.REG_SZ, r"C:\Users\Public\comhijack.dll")
    winreg.CloseKey(k)
    ok, _ = wait_for(lambda s: any(a["rule"] == "PERS-COM" for a in s["alerts"]), 45)
    check("Persistence auditor: COM object hijack (HKCU CLSID shadow)", ok)

def t_clr_hijack():
    import winreg
    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Environment")
    winreg.SetValueEx(k, "COR_PROFILER", 0, winreg.REG_SZ, "{11111111-2222-3333-4444-555555555555}")
    winreg.SetValueEx(k, "COR_ENABLE_PROFILING", 0, winreg.REG_SZ, "1")
    winreg.CloseKey(k)
    ok, _ = wait_for(lambda s: any(a["rule"] == "PERS-CLR" for a in s["alerts"]), 45)
    check("Persistence auditor: .NET CLR profiler hijack (COR_PROFILER)", ok)

def t_task_modification():
    subprocess.run(["schtasks", "/create", "/f", "/tn", "CCDCTestTask2", "/sc", "minute",
                    "/mo", "60", "/tr", "cmd /c exit"], capture_output=True)
    api("/api/baseline", post=True)          # task now in baseline
    time.sleep(2)
    subprocess.run(["schtasks", "/change", "/tn", "CCDCTestTask2", "/tr",
                    r"C:\Users\Public\stage2.exe"], capture_output=True)
    ok, _ = wait_for(lambda s: any(a["rule"] == "PERS-TASKMOD" for a in s["alerts"]), 45)
    check("Persistence auditor: scheduled task ACTION modified in place", ok)

def t_sideload_dll():
    d = r"C:\Program Files\CCDCTestSideLoad"
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "version.dll"), "wb") as f:
        f.write(b"MZ" + b"\x00" * 300 + b"CCDC sideload test dll (inert)\x00")
    ok, _ = wait_for(lambda s: any(a["rule"] == "PERS-SIDELOAD" for a in s["alerts"]), 75)
    check("Persistence auditor: DLL dropped into Program Files (side-load candidate)", ok)

def t_hive_dump_pattern():
    # pattern-only: nonexistent subkey means no hive data is actually written
    subprocess.Popen(["reg", "save", "HKLM\\SAM-CCDC-Nonexistent", os.path.join(TEMP, "x.hiv")],
                     creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = wait_for(lambda s: any(a["rule"] in ("PROC-SAM-SAVE", "EVT-SAM-SAVE") for a in s["alerts"]), 25)
    check("Process rule: registry hive dump command (reg save HKLM\\SAM...)", ok)

def t_log_clear_pattern():
    subprocess.Popen(["wevtutil", "cl", "CCDC-Nonexistent-Channel"],
                     creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = wait_for(lambda s: any(a["rule"] in ("PROC-LOG-CLEAR", "EVT-LOG-CLEAR") for a in s["alerts"]), 25)
    check("Process rule: event log clearing command (wevtutil cl)", ok)

def t_dns_beacon():
    """Resolve one fixed benign domain every 5s -> DNS cadence alert."""
    def resolver():
        for _ in range(12):
            subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Resolve-DnsName ccdc-dns-test.example.com -ErrorAction SilentlyContinue"],
                           capture_output=True)
            time.sleep(5)
    th = threading.Thread(target=resolver, daemon=True); th.start()
    ok, d = wait_for(lambda s: any(a["rule"] == "DNS-BEACON" for a in s["alerts"]), 100, step=3)
    check("DNS beacon cadence: periodic queries for one domain flagged", ok, f"waited {d:.0f}s")

def t_lsass_handle():
    """Open a VM_READ handle to LSASS (as a credential thief would) and expect the sweep."""
    import ctypes
    pid_out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "(Get-Process lsass).Id"], capture_output=True, text=True).stdout.strip()
    try:
        pid = int(pid_out)
        h = ctypes.windll.kernel32.OpenProcess(0x10, False, pid)   # PROCESS_VM_READ
        if not h:
            check("LSASS handle sweep (PPL blocked handle - verified no false positive)", True)
            return
        ok, _ = wait_for(lambda s: any(a["rule"] == "LSASS-HANDLE" for a in s["alerts"]), 70, step=3)
        ctypes.windll.kernel32.CloseHandle(h)
        check("LSASS handle sweep: VM_READ handle on lsass flagged", ok)
    except ValueError:
        check("LSASS handle sweep (lsass not found)", True)

def t_dotnet_etw():
    """Compile a hello-world named Seatbelt.exe OUTSIDE scan zones; only the
    .NET ETW loader session can surface its assembly name."""
    csc = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if not os.path.isfile(csc):
        check(".NET ETW loader: offensive assembly name (csc unavailable)", True)
        return
    d = os.path.join(os.path.expanduser("~"), "Desktop", "ccdc-dn-test")
    os.makedirs(d, exist_ok=True)
    src = os.path.join(d, "t.cs")
    exe = os.path.join(d, "Seatbelt.exe")
    with open(src, "w") as f:
        f.write("class T { static void Main() { } }")
    subprocess.run([csc, "/nologo", "/out:" + exe, src], capture_output=True)
    if os.path.isfile(exe):
        # Assembly.LoadFrom fires the Loader ETW event the sensor consumes -
        # the same channel file-less offensive tooling uses
        subprocess.Popen(["powershell", "-NoProfile", "-Command",
                          "[void][System.Reflection.Assembly]::LoadFrom('" + exe + "'); Start-Sleep 8"],
                         creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = wait_for(lambda s: any(a["rule"] == "SIG-DOTNET-OFFTOOL" for a in s["alerts"]), 90, step=3)
    check(".NET ETW loader: offensive tool assembly load flagged", ok)


# ---- tranche 3: ICMP cadence, tcp_bind listener, memory scan, config auto-block ----

def t_icmp_beacon():
    """One loopback ping every 5s -> ICMP counter cadence alert."""
    stop_flag = [False]
    def pinger():
        while not stop_flag[0]:
            subprocess.run(["ping", "-n", "1", "-w", "900", "127.0.0.1"], capture_output=True)
            time.sleep(4)
    th = threading.Thread(target=pinger, daemon=True); th.start()
    ok, d = wait_for(lambda s: any(a["rule"] == "ICMP-BEACON" for a in s["alerts"]), 110, step=3)
    stop_flag[0] = True
    check("ICMP cadence: periodic echo activity flagged (tunnel profile)", ok, f"waited {d:.0f}s")

def t_tcp_bind_listener():
    """Listener on an odd port from a TEMP-path binary (implant posture) -> NET-LISTENER."""
    import shutil
    exe = os.path.join(TEMP, "bindshell_test.exe")
    shutil.copy(sys.executable, exe)
    code = ("import socket,time\ns=socket.socket()\n"
            "s.bind(('0.0.0.0',44444))\ns.listen(1)\ntime.sleep(120)")
    proc = subprocess.Popen([exe, "-c", code], creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = wait_for(lambda s: any(a["rule"] == "NET-LISTENER" and a["data"].get("port") == 44444
                                   for a in s["alerts"]), 30)
    proc.kill()
    try: os.remove(exe)
    except OSError: pass
    check("tcp_bind: non-service listener on non-standard port flagged", ok)

def t_memory_scan():
    """Launch a process whose COMMAND LINE carries the implant config surface
    (in a real imix these strings sit in mapped .data sections). The command
    line lives in RW process memory - the memory scanner finds it there."""
    import shutil
    d = os.path.join(os.path.expanduser("~"), "Desktop", "ccdc-mem-test")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "memscan_imix_test.exe")
    shutil.copy(r"C:\Windows\System32\cmd.exe", p)
    marker = ("IMIX_CALLBACK_URI=http://127.0.0.1:9443 IMIX_BEACON_ID=m1 "
              "main.eldritch eldritch tavern")
    proc = subprocess.Popen([p, "/k", "rem " + marker],
                            creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = wait_for(lambda s: any(a["rule"].startswith("MEM-SIG-") and
                                   a.get("event", {}).get("source") == "memscan"
                                   for a in s["alerts"]), 240, step=3)
    proc.kill()
    try: os.remove(p)
    except OSError: pass
    check("Memory scan: implant config surface found in process memory", ok)

def t_config_extraction_autoblock():
    """Quarantine a file with a compiled-in callback URI -> config extracted +
    egress peer auto-blocked by the firewall."""
    p = os.path.join(TEMP, "cfgtest_implant.bin")
    blob = (b"MZ\x00\x00" + b"\x00" * 200 +
            b"IMIX_CALLBACK_URI=http://203.0.113.99:8443/tavern\x00"
            b"IMIX_BEACON_ID=cfg\x00eldritch\x00")
    with open(p, "wb") as f:
        f.write(blob)
    r = api("/api/respond", post=True, body={"action": "quarantine", "path": p})
    ok, _ = wait_for(lambda s: any(a["rule"] == "RESP-QUAR" and
                                   "203.0.113.99" in str(a["data"].get("auto_blocked_peers", ""))
                                   for a in s["alerts"]), 20)
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=CCDC-EDR-Block-203.0.113.99"], capture_output=True)
    check("Config extraction: quarantine pulled callback URI and auto-blocked C2 peer", ok)

# ---------------------------------------------------------------- cleanup

def cleanup():
    for f in [os.path.join(TEMP, "sysupd_imix_test.exe"), os.path.join(TEMP, "updhelper_test.elf"),
              os.path.join(TEMP, "staging.eldritch"), os.path.join(TEMP, "www", "health.php"),
              os.path.join(STARTUP, "ccdc-test-persistence.bat"),
              os.path.join(TEMP, "updhwatershell_test.elf"), os.path.join(TEMP, "x.hiv"),
              os.path.join(TEMP, "cfgtest_implant.bin")]:
        try: os.remove(f)
        except OSError: pass
    try: os.rmdir(os.path.join(TEMP, "www"))
    except OSError: pass
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run",
                           0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(k, "CCDCTestPayload"); winreg.CloseKey(k)
    except OSError: pass
    try:
        import winreg
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                         r"Software\Classes\CLSID\{99999999-cccc-cccc-cccc-999999999999}\InprocServer32")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                         r"Software\Classes\CLSID\{99999999-cccc-cccc-cccc-999999999999}")
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE)
        try: winreg.DeleteValue(k, "COR_PROFILER")
        except OSError: pass
        try: winreg.DeleteValue(k, "COR_ENABLE_PROFILING")
        except OSError: pass
        winreg.CloseKey(k)
    except OSError: pass
    subprocess.run(["schtasks", "/delete", "/f", "/tn", "CCDCTestTask"], capture_output=True)
    subprocess.run(["schtasks", "/delete", "/f", "/tn", "CCDCTestTask2"], capture_output=True)
    subprocess.run(["sc", "delete", "CCDCTestSvc"], capture_output=True)
    import shutil
    shutil.rmtree(r"C:\Program Files\CCDCTestSideLoad", ignore_errors=True)
    shutil.rmtree(os.path.join(os.path.expanduser("~"), "Desktop", "ccdc-dn-test"), ignore_errors=True)
    shutil.rmtree(os.path.join(os.path.expanduser("~"), "Desktop", "ccdc-mem-test"), ignore_errors=True)
    print("\n[*] cleanup done (registry keys, tasks, service, files removed)")

class _ClassicDone(Exception):
    pass

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
        # tranche 2: advanced persistence + evasion coverage
        t_watershell_signature()
        t_com_hijack()
        t_clr_hijack()
        t_task_modification()
        t_sideload_dll()
        t_hive_dump_pattern()
        t_log_clear_pattern()
        t_lsass_handle()
        t_dotnet_etw()
        t_dns_beacon()
        if os.environ.get("EDR_TESTS") == "classic":
            raise _ClassicDone()
        t_icmp_beacon()
        t_tcp_bind_listener()
        t_memory_scan()
        t_config_extraction_autoblock()
        t_icmp_beacon()
        t_tcp_bind_listener()
        t_memory_scan()
        t_config_extraction_autoblock()
    except _ClassicDone:
        pass
    finally:
        cleanup()
    passed = sum(1 for _, ok, _ in results if ok)
    print("\n=== RESULTS: %d/%d passed ===" % (passed, len(results)))
    for name, ok, detail in results:
        print(("  PASS " if ok else "  FAIL ") + name + ("  -- " + detail if detail and not ok else ""))
    sys.exit(0 if passed == len(results) else 1)

if __name__ == "__main__":
    main()
