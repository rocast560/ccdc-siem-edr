"""Tranche-4 tests: module sideload, hook-DLL correlation, ntdll integrity,
unbacked threads, named pipes, timestomp, new cmdline rules, SPE/SSH keys.
Usage: python tests/run_tranche4.py  (EDR must be running)"""
import ctypes, json, os, shutil, socket, subprocess, sys, time, urllib.request, winreg

sys.path.insert(0, os.path.dirname(__file__))
import run_tests as rt
TEMP = rt.TEMP

def main():
    rt.api("/api/state")
    try:
        t_module_sideload()
        t_hook_dll()
        t_ntdll_patch()
        t_unbacked_thread()
        t_named_pipe()
        t_timestomp()
        t_cmdline_rules()
        t_spe_key()
    finally:
        cleanup4()
    passed = sum(1 for _, ok, _ in rt.results if ok)
    print("\n=== TRANCHE-4: %d/%d passed ===" % (passed, len(rt.results)))
    for name, ok, detail in rt.results:
        print(("  PASS " if ok else "  FAIL ") + name + ("  -- " + detail if detail and not ok else ""))
    sys.exit(0 if passed == len(rt.results) else 1)

# ---------------------------------------------------------------- tests

def t_module_sideload():
    """Load a Windows-named DLL (copied winmm.dll) from TEMP in a python child."""
    dll = os.path.join(TEMP, "winmm_test_dir", "winmm.dll")
    os.makedirs(os.path.dirname(dll), exist_ok=True)
    shutil.copy(r"C:\Windows\System32\winmm.dll", dll)
    code = ("import ctypes,time;ctypes.WinDLL(r'" + dll + "');time.sleep(150)")
    p = subprocess.Popen(["python", "-c", code], creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "MOD-SIDELOAD" and
                                      "winmm" in str(a["data"].get("module", "")).lower()
                                      for a in s["alerts"]), 120, step=3)
    p.kill()
    rt.check("Module walk: Windows-named DLL loaded outside System32 flagged", ok)

def t_hook_dll():
    """One unsigned DLL loaded into 4 processes -> HOOK-DLL correlation."""
    dll = os.path.join(TEMP, "hooktest_common.dll")
    shutil.copy(r"C:\Windows\System32\winmm.dll", dll)   # unsigned copy outside System32
    code = ("import ctypes,time;ctypes.WinDLL(r'" + dll + "');time.sleep(150)")
    procs = [subprocess.Popen(["python", "-c", code], creationflags=subprocess.CREATE_NO_WINDOW)
             for _ in range(4)]
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "HOOK-DLL" and
                                      "hooktest" in str(a["data"].get("path", "")).lower()
                                      for a in s["alerts"]), 150, step=3)
    for p in procs: p.kill()
    rt.check("Hook-DLL correlation: one module across 4 processes flagged", ok)

def t_ntdll_patch():
    """Patch a byte of ntdll .text in a child process -> NTDLL-TAMPER."""
    code = r'''
import ctypes, struct, time
k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong,
                               ctypes.POINTER(ctypes.c_ulong)]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.c_void_p]
base = k32.GetModuleHandleW("ntdll.dll")
hdr = ctypes.string_at(base, 0x400)                    # headers fit in the first page
pe = struct.unpack_from("<I", hdr, 0x3C)[0]
nsec = struct.unpack_from("<H", hdr, pe+6)[0]
optsz = struct.unpack_from("<H", hdr, pe+20)[0]
sec = pe+24+optsz
tva = 0
for i in range(nsec):
    o = sec+i*40
    if hdr[o:o+6] == b".text":
        tsz, tva = struct.unpack_from("<II", hdr, o+8)
        break
addr = base + tva
old = ctypes.c_ulong(0)
k32.VirtualProtect(ctypes.c_void_p(addr), 16, 0x40, ctypes.byref(old))
k32.WriteProcessMemory(k32.GetCurrentProcess(), ctypes.c_void_p(addr), b"\xC3", 1, None)
print("PATCHED", flush=True)
time.sleep(120)
'''
    p = subprocess.Popen(["python", "-c", code], stdout=subprocess.PIPE,
                         creationflags=subprocess.CREATE_NO_WINDOW, text=True)
    p.stdout.readline()
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "NTDLL-TAMPER" for a in s["alerts"]), 150, step=3)
    p.kill()
    rt.check("Memory integrity: patched ntdll .text flagged (inline hook / unhooking)", ok)

def t_unbacked_thread():
    """Create a thread whose start address is in private RWX memory."""
    code = r'''
import ctypes, time
k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
mem = k32.VirtualAlloc(None, 4096, 0x3000, 0x40)   # RWX private
ctypes.memmove(mem, b"\xEB\xFE", 2)                # jmp self - thread stays alive
tid = ctypes.c_ulong(0)
k32.CreateThread(None, 0, ctypes.c_void_p(mem), None, 0, ctypes.byref(tid))
print("THREAD", flush=True)
time.sleep(120)
'''
    p = subprocess.Popen(["python", "-c", code], stdout=subprocess.PIPE,
                         creationflags=subprocess.CREATE_NO_WINDOW, text=True)
    p.stdout.readline()
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "THREAD-UNBACKED" for a in s["alerts"]), 150, step=3)
    p.kill()
    rt.check("Thread scan: thread start address in private RWX flagged (injection)", ok)

def t_named_pipe():
    """Create a C2-named pipe from a TEMP-path process."""
    exe = os.path.join(TEMP, "pipetest_host.exe")
    shutil.copy(sys.executable, exe)
    code = ("import ctypes,time;k=ctypes.windll.kernel32;"
            "k.CreateNamedPipeW(r'\\\\.\\pipe\\msagent_ccdctest',3,0,1,0,0,0,None);time.sleep(150)")
    p = subprocess.Popen([exe, "-c", code], creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "NET-PIPE" and
                                      "ccdc" in str(a["data"].get("pipe", "")).lower()
                                      for a in s["alerts"]), 60)
    p.kill()
    rt.check("Named pipes: C2-named pipe flagged", ok)

def t_timestomp():
    """File with mtime backdated 2 years -> TIME-STOMP on scan."""
    p = os.path.join(TEMP, "timestomped_test.exe")
    shutil.copy(r"C:\Windows\System32\cmd.exe", p)
    two_years = 2 * 365 * 24 * 3600
    os.utime(p, (time.time() - two_years, time.time() - two_years))
    rt.api("/api/scan", post=True)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "TIME-STOMP" and
                                      "timestomped" in str(a["data"].get("path", "")).lower()
                                      for a in s["alerts"]), 30)
    rt.check("Timestomp: backdated mtime vs ctime divergence flagged", ok)

def t_cmdline_rules():
    """Pattern-only invocations for the new cmdline rules (nonexistent targets)."""
    cases = [
        ("PROC-EGRESS-TOOL", ["cmd", "/c", "chisel", "client", "127.0.0.1:1", "r:socks"]),
        ("PROC-RMM-TOOL", ["cmd", "/c", "anydesk.exe", "--nonexistent-flag"]),
        ("PROC-NETSH-FIREWALL", ["netsh", "advfirewall", "firewall", "add", "rule",
                                 "name=ccdc-test-noop", "dir=in", "action=block",
                                 "remoteip=203.0.113.98"]),
        ("NET-DEADDROP", ["curl", "-s", "--max-time", "1",
                          "https://raw.githubusercontent.com/ccdc/nonexistent/repo/xy"]),
    ]
    for rid, cmd in cases:
        subprocess.Popen(cmd, creationflags=subprocess.CREATE_NO_WINDOW)
    ok_egr, _ = rt.wait_for(lambda s: any(a["rule"] in ("PROC-EGRESS-TOOL", "EVT-EGRESS-TOOL")
                                          for a in s["alerts"]), 30)
    ok_rmm, _ = rt.wait_for(lambda s: any(a["rule"] in ("PROC-RMM-TOOL", "EVT-RMM-TOOL")
                                          for a in s["alerts"]), 20)
    ok_nsh, _ = rt.wait_for(lambda s: any(a["rule"] in ("PROC-NETSH-FIREWALL", "EVT-NETSH-FIREWALL")
                                          for a in s["alerts"]), 20)
    ok_dd, _ = rt.wait_for(lambda s: any(a["rule"] in ("NET-DEADDROP", "EVT-DEADDROP")
                                         for a in s["alerts"]), 30)
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=ccdc-test-noop"], capture_output=True)
    rt.check("Cmdline rule: egress/tunnel tool (chisel)", ok_egr)
    rt.check("Cmdline rule: RMM tool (anydesk)", ok_rmm)
    rt.check("Cmdline rule: firewall rule modification (netsh)", ok_nsh)
    rt.check("Cmdline rule: dead-drop fetch (raw.githubusercontent)", ok_dd)

def t_spe_key():
    """SilentProcessExit MonitorProcess hijack plant -> PERS-SPE."""
    k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit")
    winreg.SetValueEx(k, "MonitorProcess", 0, winreg.REG_SZ, r"C:\Users\Public\spe_payload.exe")
    winreg.CloseKey(k)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "PERS-SPE" for a in s["alerts"]), 75)
    rt.check("Persistence auditor: SilentProcessExit MonitorProcess hijack", ok)

# ---------------------------------------------------------------- cleanup

def cleanup4():
    for d in [os.path.join(TEMP, "winmm_test_dir")]:
        shutil.rmtree(d, ignore_errors=True)
    for f in [os.path.join(TEMP, "hooktest_common.dll"), os.path.join(TEMP, "timestomped_test.exe"),
              os.path.join(TEMP, "pipetest_host.exe")]:
        try: os.remove(f)
        except OSError: pass
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit")
    except OSError:
        pass
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=ccdc-test-noop"], capture_output=True)
    print("\n[*] tranche-4 cleanup done")

if __name__ == "__main__":
    main()
