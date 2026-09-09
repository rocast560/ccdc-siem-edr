"""Tranche-6 tests: watershell-on-Windows detection checklist.
Usage: python tests/run_tranche6.py  (EDR must be running)"""
import os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(__file__))
import run_tests as rt
TEMP = rt.TEMP

def main():
    rt.api("/api/state")
    try:
        t_mingw_signature()
        t_masquerade()
        t_shell_spawner()
        t_service_binary_scan()
    finally:
        cleanup6()
    passed = sum(1 for _, ok, _ in rt.results if ok)
    print("\n=== TRANCHE-6: %d/%d passed ===" % (passed, len(rt.results)))
    for name, ok, detail in rt.results:
        print(("  PASS " if ok else "FAIL ") + name + ("  -- " + detail if detail and not ok else ""))
    sys.exit(0 if passed == len(rt.results) else 1)

def t_mingw_signature():
    """Fake PE carrying MinGW/g++ build markers -> SIG-MINGW on write-scan."""
    p = os.path.join(TEMP, "mingw_test.exe")
    blob = (b"MZ" + b"\x00" * 300 +
            b"GCC: (GNU) 13.2.0\x00" +
            b"libgcc_s_dw2-1.dll\x00" +
            b"__gxx_personality_v0\x00" +
            b"mingw-w64 x86_64\x00" +
            b"libstdc++-6.dll\x00")
    with open(p, "wb") as f:
        f.write(blob)
    rt.api("/api/scan", post=True)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "SIG-MINGW" and
                                      "mingw_test" in str(a["data"].get("path", ""))
                                      for a in s["alerts"]), 30)
    rt.check("MinGW artifacts: g++-compiled binary signature flagged", ok)

def t_masquerade():
    """cmd.exe copy renamed svchost.exe in TEMP, launched -> PROC-MASQ."""
    p = os.path.join(TEMP, "svchost.exe")
    shutil.copy(r"C:\Windows\System32\cmd.exe", p)
    proc = subprocess.Popen([p, "/k", "echo held"], creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "PROC-MASQ" and
                                      a["data"].get("pid") == proc.pid for a in s["alerts"]),
                        30)
    proc.kill()
    rt.check("Masquerading: critical system binary name outside Windows flagged", ok)

def t_shell_spawner():
    """Unknown TEMP-path binary spawns cmd.exe -> SPAWN-SHELL."""
    host = os.path.join(TEMP, "updater_helper.exe")
    shutil.copy(r"C:\Windows\System32\cmd.exe", host)
    proc = subprocess.Popen([host, "/c", "cmd /k echo held"],
                            creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "SPAWN-SHELL" and
                                      "updater_helper" in str(a["data"].get("parent", ""))
                                      for a in s["alerts"]), 30)
    proc.kill()
    rt.check("Shell spawner: user-path binary spawning interpreter flagged", ok)

def t_service_binary_scan():
    """Service installed pointing at a MinGW-marker binary -> signature on the
    service binary via the auditor (not just the 7045 event)."""
    binp = os.path.join(TEMP, "svc_mingw_implant.exe")
    with open(binp, "wb") as f:
        f.write(b"MZ" + b"\x00" * 200 + b"GCC: (GNU) 12.1.0\x00libgcc\x00mingw32\x00")
    subprocess.run(["sc", "create", "CCDCTestMingwSvc", "binPath=", binp],
                   capture_output=True)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "SIG-MINGW" and
                                      "svc_mingw" in str(a["data"].get("binary", a["data"].get("path", "")))
                                      for a in s["alerts"]), 75)
    subprocess.run(["sc", "delete", "CCDCTestMingwSvc"], capture_output=True)
    rt.check("Service persistence: 7045 service binary signature-scanned (user dir, unsigned)", ok)

def cleanup6():
    for f in ("mingw_test.exe", "svchost.exe", "updater_helper.exe", "svc_mingw_implant.exe"):
        try: os.remove(os.path.join(TEMP, f))
        except OSError: pass
    subprocess.run(["sc", "delete", "CCDCTestMingwSvc"], capture_output=True)
    print("\n[*] tranche-6 cleanup done")

if __name__ == "__main__":
    main()
