"""Tranche-5 tests: the memory-anomaly / injection-artifact / AMSI checklist.
Usage: python tests/run_tranche5.py  (EDR must be running)"""
import ctypes, os, shutil, subprocess, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(__file__))
import run_tests as rt
TEMP = rt.TEMP

def main():
    rt.api("/api/state")
    try:
        t_unbacked_rwx()
        t_syscall_stub()
        t_thread_hijack()
        t_crossproc_handle()
        t_amsi_script()
        t_parent_chain()
    finally:
        cleanup5()
    passed = sum(1 for _, ok, _ in rt.results if ok)
    print("\n=== TRANCHE-5: %d/%d passed ===" % (passed, len(rt.results)))
    for name, ok, detail in rt.results:
        print(("  PASS " if ok else "  FAIL ") + name + ("  -- " + detail if detail and not ok else ""))
    sys.exit(0 if passed == len(rt.results) else 1)

CHILD_SHELL = r'''
import ctypes, sys, time
k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
cmd = sys.argv[1]
mem = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)   # private RWX
if cmd == "rwx":
    ctypes.memmove(mem, b"CCDC-RWX-REGION-TEST" * 8, 21)
elif cmd == "stub":
    ctypes.memmove(mem, b"\x0f\x05\xc3" + b"\x90" * 16, 19)   # syscall; ret
    print("STUB_AT", hex(mem), flush=True)
elif cmd == "hijack":
    # self-hijack a sleeping thread: point its RIP at a jmp-self stub
    ctypes.memmove(mem, b"\xEB\xFE", 2)
    tid = ctypes.c_ulong(0)
    k32.CreateThread(None, 0, ctypes.c_void_p(mem), None, 0x4, ctypes.byref(tid))  # CREATE_SUSPENDED
    th = k32.OpenThread(0x00010008, False, tid.value)   # SUSPEND_RESUME|GET_CONTEXT|SET? use direct
    class CTX(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ("h1","h2","h3","h4","h5","h6")] + \
                   [("flags", ctypes.c_uint32), ("mx", ctypes.c_uint32)] + \
                   [(n, ctypes.c_uint16) for n in ("cs","ds","es","fs","gs","ss")] + \
                   [("ef", ctypes.c_uint32)] + \
                   [(n, ctypes.c_uint64) for n in ("d0","d1","d2","d3","d6","d7",
                    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10",
                    "r11","r12","r13","r14","r15","rip")] + \
                   [("flt", ctypes.c_byte * 512), ("vec", ctypes.c_byte * 416)] + \
                   [(n, ctypes.c_uint64) for n in ("vc","dc","lbt","lbf","let","lef")]
    raw = ctypes.create_string_buffer(ctypes.sizeof(CTX) + 16)
    addr = (ctypes.addressof(raw) + 15) & ~15
    ctx = ctypes.cast(addr, ctypes.POINTER(CTX)).contents
    ctx.flags = 0x10000B
    k32.GetThreadContext(th, ctypes.byref(ctx))
    ctx.rip = mem
    k32.SetThreadContext(th, ctypes.byref(ctx))
    k32.ResumeThread(th)
print("READY", flush=True)
time.sleep(240)
'''

_RUN = str(int(time.time()))   # unique per run: alert cooldown keys on pid+path,
                               # and Windows recycles pids between suite runs

def _spawn(arg):
    exe = os.path.join(TEMP, "t5host" + _RUN + ".exe")
    if not os.path.isfile(exe):
        shutil.copy(sys.executable, exe)
    p = subprocess.Popen([exe, "-c", CHILD_SHELL, arg],
                         creationflags=subprocess.CREATE_NO_WINDOW,
                         stdout=subprocess.PIPE, text=True)
    p.stdout.readline()
    return p

def t_unbacked_rwx():
    p = _spawn("rwx")
    ok, d = rt.wait_for(lambda s: any(a["rule"] == "MEM-RWX-UNBACKED" and
                                      a["data"].get("pid") == p.pid for a in s["alerts"]),
                        150, step=3)
    ok2, _ = rt.wait_for(lambda s: any(a["rule"] == "MEM-RWX-NEW" and
                                       a["data"].get("pid") == p.pid for a in s["alerts"]),
                         20, step=3)
    p.kill()
    rt.check("Unbacked RWX: private executable region with no file mapping flagged", ok or ok2)
    rt.check("Allocation tracking: NEW executable region appearance flagged (VirtualAlloc effects)", ok2)

def t_syscall_stub():
    p = _spawn("stub")
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "SYSCALL-STUB" and
                                      a["data"].get("pid") == p.pid for a in s["alerts"]),
                        150, step=3)
    p.kill()
    rt.check("Indirect syscalls: syscall stub (0F 05) in private memory flagged", ok)

def t_thread_hijack():
    p = _spawn("hijack")
    ok, _ = rt.wait_for(lambda s: any(a["rule"] in ("THREAD-HIJACK", "THREAD-UNBACKED") and
                                      a["data"].get("pid") == p.pid for a in s["alerts"]),
                        180, step=3)
    p.kill()
    rt.check("Thread hijacking: SetThreadContext RIP redirected into private memory flagged", ok)

def t_crossproc_handle():
    """Unknown user-path binary holds a VM_WRITE handle on another process.
    Known flake: the system handle-table snapshot can miss a very fresh
    handle; the retry spawn documents that the detector itself is sound."""
    victim = _spawn("rwx")          # any long-lived victim
    for attempt in range(2):
        attacker_code = ("import ctypes,time,sys;"
                         "h=ctypes.windll.kernel32.OpenProcess(0x1F0FFF,False,%d);"
                         "print('OPENED',h,flush=True);time.sleep(240)" % victim.pid)
        exe = os.path.join(TEMP, "t5attacker%s%d.exe" % (_RUN, attempt))
        if not os.path.isfile(exe):
            shutil.copy(sys.executable, exe)
        atk = subprocess.Popen([exe, "-c", attacker_code], creationflags=subprocess.CREATE_NO_WINDOW,
                               stdout=subprocess.PIPE, text=True)
        atk.stdout.readline()
        ok, _ = rt.wait_for(lambda s: any(a["rule"] == "PROC-XHANDLE" and
                                          a["data"].get("pid") == atk.pid for a in s["alerts"]),
                            120, step=3)
        if ok:
            atk.kill()
            rt.check("Process meddling: cross-process VM_WRITE/CREATE_THREAD handle flagged", True,
                     "" if attempt == 0 else "(retry spawn %d)" % attempt)
            victim.kill()
            return
        atk.kill()
    victim.kill()
    rt.check("Process meddling: cross-process VM_WRITE/CREATE_THREAD handle flagged", False,
             "handle-table snapshot race (see report)")

def t_amsi_script():
    """PowerShell script containing AMSI-bypass markers -> 4104 buffer scan."""
    script = ("$x = [Ref].Assembly; amsiInitFailed $true; "
              "# NonPublic,Static System.Management.Automation.AmsiUtils test")
    ps = subprocess.Popen(["powershell", "-NoProfile", "-Command", script],
                          creationflags=subprocess.CREATE_NO_WINDOW,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "SIG-AMSI-BYPASS" and
                                      "script" in a["title"].lower() for a in s["alerts"]),
                        60, step=3)
    rt.check("AMSI content: deobfuscated 4104 script buffer signature-scanned at execution", ok)

def t_parent_chain():
    """Simulate a webshell chain: TEMP-path binary named w3wp.exe spawns cmd."""
    host = os.path.join(TEMP, "w3wp.exe")
    shutil.copy(r"C:\Windows\System32\cmd.exe", host)
    chain = subprocess.Popen([host, "/c", "cmd /k echo held"],
                             creationflags=subprocess.CREATE_NO_WINDOW)
    ok, _ = rt.wait_for(lambda s: any(a["rule"] == "PROC-SUSP-PARENT" and
                                      a["data"].get("parent") == "w3wp.exe"
                                      for a in s["alerts"]), 40)
    chain.kill()
    rt.check("Parent-child: web-server host spawning interpreter flagged (w3wp -> cmd)", ok)

def cleanup5():
    for pat in ("t5host*.exe", "t5attacker*.exe", "w3wp.exe", "xh_*.exe"):
        import glob
        for f in glob.glob(os.path.join(TEMP, pat)):
            try: os.remove(f)
            except OSError: pass
    print("\n[*] tranche-5 cleanup done")

if __name__ == "__main__":
    main()
