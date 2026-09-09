"""Benign test implant — lights up multiple sensor families on ONE pid:

  - private RWX allocation (MEM-RWX-UNBACKED, MEM-RWX-NEW)
  - syscall-stub bytes 0F 05 C3 in that region (SYSCALL-STUB)
  - embedded implant config surface strings (SIG-REALM-IMIX in memory mode)
  - 5s +-0.4s jittered TCP beacon to 127.0.0.1:9101 (NET-BEACON cadence)

It does nothing else: no exec, no writes, single connection per cycle.
Run with the workspace test venv so the image path is unprotected:
  .t/Scripts/python.exe tests/fake_implant.py
"""
import ctypes, random, socket, time

k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE = 0x1000, 0x2000, 0x40

blob = (b"\x0f\x05\xc3" + b"\x90" * 61 +
        b"IMIX_CALLBACK_URI=tcp://127.0.0.1:9101\x00"
        b"IMIX_SERVER_PUBKEY=AAABBBCCCDDD\x00"
        b"IMIX_BEACON_ID=test-implant-01\x00"
        b"IMIX_GUARDRAILS=ccdc-blue\x00"
        b"IMIX_CONFIG=v1\x00"
        b"main.eldritch tavern\x00")
ptr = k32.VirtualAlloc(None, len(blob) + 0x2000,
                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
if ptr:
    ctypes.memmove(ptr, blob, len(blob))
    print("implant blob at 0x%x" % ptr, flush=True)

PEER = ("127.0.0.1", 9101)
while True:
    try:
        s = socket.create_connection(PEER, timeout=2)
        s.sendall(b"imix-beacon")
        try:
            s.recv(64)
        except OSError:
            pass
        time.sleep(5 + random.uniform(-0.4, 0.4))   # hold the session for the cycle
        s.close()
    except OSError:
        time.sleep(5 + random.uniform(-0.4, 0.4))
