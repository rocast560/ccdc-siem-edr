#!/usr/bin/env python3
"""sleep_crypt_implant — purple-team sleep-encryption beacon simulator.

Exercises, honestly but safely, the memory-evasion techniques documented in
playbooks/README.md (Ekko/Cronos family, thread-driven variant — no ROP):

  - payload buffer lives in a PRIVATE page allocated at runtime
  - on wake: page flips to RWX, buffer is XOR-decrypted IN PLACE, the beacon
    connects to LOOPBACK ONLY, then...
  - before sleep: buffer is re-encrypted in place, keystream destroyed, page
    flips back to RW, working set trimmed (plaintext never pages out)
  - long jittered sleep -> memory scanners see only ciphertext

While AWAKE the plaintext buffer contains implant-style config strings, so
signature scanners have a window to catch it; while ASLEEP they don't —
scan timing is the detection lesson.

No command channel, no exfiltration, no self-spreading. Loopback only.
Run directly for testing, or deployed as XOR ciphertext + loader stub by
wb2-sleep-crypt.ps1 / lb2-sleep-crypt.sh.
"""
import ctypes, os, random, socket, sys, time

# ----------------------------------------------------------------- CONFIG
PEER_HOST = "127.0.0.1"      # loopback ONLY (safety contract)
PEER_PORT = 9101
SLEEP_S   = 45               # encrypted sleep between cycles
WAKE_S    = 6                # plaintext window per cycle
JITTER    = 0.30             # +-30% cadence jitter
# plaintext that lives in the encrypted buffer (what scanners can find ONLY
# while the implant is awake — edit to exercise different signatures)
PLAINTEXT = (b"IMIX_CALLBACK_URI=tcp://127.0.0.1:9101\r\n"
             b"IMIX_BEACON_ID=playbook-sleepcrypt\r\n"
             b"IMIX_GUARDRAILS=ccdc-blue\r\n")
# -----------------------------------------------------------------------

IS_WIN = sys.platform == "win32"

def _win_api():
    k32 = ctypes.windll.kernel32
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32,
                                   ctypes.POINTER(ctypes.c_uint32)]
    k32.SetProcessWorkingSetSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t]
    return k32

def _lin_api():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    return libc

def xor_stream(buf, seed):
    """XOR the buffer in place with a seeded keystream, then drop the RNG."""
    rng = random.Random(seed)
    for i in range(len(buf)):
        buf[i] ^= rng.randrange(256)
    del rng

def main():
    n = max(len(PLAINTEXT), 0x1000)
    seed = os.urandom(16)
    if IS_WIN:
        k32 = _win_api()
        PAGE_RW, PAGE_RWX = 0x04, 0x40
        MEM = 0x3000  # COMMIT | RESERVE
        page = k32.VirtualAlloc(None, n, MEM, PAGE_RW)
        if not page:
            sys.exit("VirtualAlloc failed")
        # write plaintext then encrypt once so the run starts "asleep"
        ctypes.memmove(page, PLAINTEXT, len(PLAINTEXT))
        raw = (ctypes.c_ubyte * len(PLAINTEXT)).from_address(page)
        xor_stream(raw, seed)
        def set_prot(prot):
            old = ctypes.c_uint32(0)
            k32.VirtualProtect(page, n, prot, ctypes.byref(old))
        def trim():
            k32.SetProcessWorkingSetSize(ctypes.c_void_p(-1), -1, -1)
    else:
        libc = _lin_api()
        RW, RWX = 3, 7            # PROT_READ|WRITE, READ|WRITE|EXEC
        MAP_PRIVATE, MAP_ANON = 0x02, 0x20
        page = libc.mmap(None, n, RW, MAP_PRIVATE | MAP_ANON, -1, 0)
        if page in (0, -1, None) or page == ctypes.c_void_p(-1).value:
            sys.exit("mmap failed")
        ctypes.memmove(page, PLAINTEXT, len(PLAINTEXT))
        raw = (ctypes.c_ubyte * len(PLAINTEXT)).from_address(page)
        xor_stream(raw, seed)
        def set_prot(prot):
            libc.mprotect(page, n, prot)
        def trim():
            libc.madvise(ctypes.c_void_p(page), n, 4)   # MADV_DONTNEED

    print("sleep-crypt implant: pid %d, %s page at %#x (%d-byte buffer)"
          % (os.getpid(), "win" if IS_WIN else "linux", page, len(PLAINTEXT)), flush=True)
    cycle = 0
    while True:
        cycle += 1
        # ---- WAKE: decrypt, flip exec, beacon ----------------------------
        xor_stream(raw, seed)                 # decrypt in place
        set_prot(PAGE_RWX if IS_WIN else RWX)
        t0 = time.time()
        try:
            s = socket.create_connection((PEER_HOST, PEER_PORT), timeout=2)
            s.sendall(b"sleepcrypt")
            s.close()
        except OSError:
            pass                              # no listener? cadence still ticks
        while time.time() - t0 < WAKE_S:
            time.sleep(0.5)
        # ---- SLEEP: re-encrypt, drop exec, trim working set ---------------
        xor_stream(raw, seed)                 # re-encrypt in place
        set_prot(PAGE_RW if IS_WIN else RW)
        trim()
        jitter = SLEEP_S * (1 + random.uniform(-JITTER, JITTER))
        time.sleep(jitter)

if __name__ == "__main__":
    if "--status" in sys.argv:
        print("run state lives in the process; check the EDR Implants screen")
        sys.exit(0)
    main()
