"""Tranche-8 test: RW -> RX permission-transition detection (MEM-PROMOTE).
Usage: python tests/run_tranche8.py  (EDR must be running)"""
import os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(__file__))
import run_tests as rt
TEMP = rt.TEMP

CHILD = r'''
import ctypes, os, time
k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
# allocate READ-WRITE (never RWX), write a marker, report the address
mem = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x04)   # MEM_COMMIT|RESERVE, PAGE_READWRITE
ctypes.memmove(mem, b"CCDC-RW-BEFORE-FLIP" * 4, 20)
print("RW_AT", hex(mem), flush=True)
flip = os.environ.get("FLIP_FILE", "")
while not os.path.exists(flip):
    time.sleep(1)
old = ctypes.c_ulong(0)
ok = k32.VirtualProtect(ctypes.c_void_p(mem), 0x1000, 0x20, ctypes.byref(old))  # PAGE_EXECUTE_READ
print("FLIPPED", ok, flush=True)
time.sleep(300)
'''

def main():
    rt.api("/api/state")
    try:
        t_promote()
    finally:
        cleanup8()
    passed = sum(1 for _, ok, _ in rt.results if ok)
    print("\n=== TRANCHE-8: %d/%d passed ===" % (passed, len(rt.results)))
    for name, ok, detail in rt.results:
        print(("  PASS " if ok else "FAIL ") + name + ("  -- " + detail if detail and not ok else ""))
    sys.exit(0 if passed == len(rt.results) else 1)

def t_promote():
    """Child allocates RW; we let a memmap pass record it, then flip to RX
    via VirtualProtect -> MEM-PROMOTE must fire (and NOT merely the generic
    unbacked-RWX story)."""
    exe = os.path.join(TEMP, "t8host.exe")
    if not os.path.isfile(exe):
        shutil.copy(sys.executable, exe)
    flip = os.path.join(TEMP, "t8_flip.marker")
    env = dict(os.environ, FLIP_FILE=flip)
    p = subprocess.Popen([exe, "-c", CHILD], creationflags=subprocess.CREATE_NO_WINDOW,
                         stdout=subprocess.PIPE, text=True, env=env)
    line = p.stdout.readline().split()
    print("[*] child RW region at", line[1] if len(line) > 1 else "?")
    # wait for a memmap pass to record the region as read-write (75s cadence)
    print("[*] waiting 95s for the sensor to record the RW region...")
    time.sleep(95)
    # flip to RX
    open(flip, "w").write("go")
    print("[*] flip signalled; waiting for MEM-PROMOTE...")
    ok, d = rt.wait_for(lambda s: any(a["rule"] == "MEM-PROMOTE" and
                                      a["data"].get("pid") == p.pid for a in s["alerts"]),
                        200, step=3)
    p.kill()
    rt.check("RW->RX transition: VirtualProtect permission flip flagged at the transition", ok,
             "waited %.0fs" % d)

def cleanup8():
    for f in ("t8host.exe", "t8_flip.marker"):
        try: os.remove(os.path.join(TEMP, f))
        except OSError: pass
    print("\n[*] tranche-8 cleanup done")

if __name__ == "__main__":
    main()
