"""Module-stomping detection test (benign, self-contained, fixed behavior).

Loads a COPY of a signed system DLL into this own process, then rewrites a
few bytes of the copy's in-memory .text across TWO distinct 64KB chunks —
exactly what module stomping / in-process ETW-AMSI patching looks like to a
sensor that compares loaded-module .text against disk. The on-disk file is
never modified; original bytes are restored on exit.

Expected EDR behavior: MOD-STOMPPED (critical) on the first hooks pass that
reaches this process (interval 90s, rotation covers newest processes first).

Run with the workspace interpreter copy so the trusted-image allowlist
doesn't hide the entity:
    tests/bin/implant.exe tests/self_stomp_test.py [hold_seconds=240]
"""
import ctypes, os, shutil, struct, sys, time

k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32,
                               ctypes.POINTER(ctypes.c_uint32)]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.GetCurrentProcess.restype = ctypes.c_void_p

HOLD_S = int(sys.argv[1]) if len(sys.argv) > 1 else 240
SRC = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "winmm.dll")
DST = os.path.join(os.environ.get("TEMP", "."), "ccdc-stomp-copy.dll")
PAGE_READWRITE = 0x04

shutil.copyfile(SRC, DST)
hmod = k32.LoadLibraryW(DST)
if not hmod:
    sys.exit("LoadLibrary failed")

# locate the mapped .text via the in-memory PE headers
base = hmod
pe_off = struct.unpack_from("<I", ctypes.string_at(base, 0x40), 0x3C)[0]
hdr = ctypes.string_at(base + pe_off, 64)
nsec = struct.unpack_from("<H", hdr, 6)[0]
opt_size = struct.unpack_from("<H", hdr, 20)[0]
sec_off = pe_off + 24 + opt_size
text_rva = text_size = None
for i in range(nsec):
    s = ctypes.string_at(base + sec_off + i * 40, 40)
    if s[:6].rstrip(b"\x00") == b".text":
        vsize, vaddr, _rs, _ra = struct.unpack_from("<IIII", s, 8)
        text_rva, text_size = vaddr, vsize
        break
if text_rva is None:
    sys.exit("no .text found")

# two patches, in DIFFERENT 64KB chunks (the detector's >=2-chunk threshold)
targets = [text_rva + 0x1000, text_rva + 0x11000]
targets = [t for t in targets if t + 16 < text_size] or [text_rva + 0x100]
saved = {}
old = ctypes.c_uint32(0)
wrote = ctypes.c_size_t(0)
me = k32.GetCurrentProcess()
k32.VirtualProtect(ctypes.c_void_p(base + text_rva), text_size,
                   PAGE_READWRITE, ctypes.byref(old))
for t in targets:
    addr = base + t
    saved[t] = ctypes.string_at(addr, 16)
    patch = bytes(b ^ 0x5A for b in saved[t])          # visible, reversible
    if not k32.WriteProcessMemory(me, ctypes.c_void_p(addr), patch, 16,
                                  ctypes.byref(wrote)):
        print("WriteProcessMemory failed at %#x" % t)
k32.VirtualProtect(ctypes.c_void_p(base + text_rva), text_size,
                   old.value, ctypes.byref(ctypes.c_uint32(0)))

print("stomped %s (.text rva %#x): %d chunks patched, holding %ds"
      % (os.path.basename(DST), text_rva, len(saved), HOLD_S), flush=True)
try:
    time.sleep(HOLD_S)
finally:
    k32.VirtualProtect(ctypes.c_void_p(base + text_rva), text_size,
                       PAGE_READWRITE, ctypes.byref(ctypes.c_uint32(0)))
    for t, orig in saved.items():
        k32.WriteProcessMemory(me, ctypes.c_void_p(base + t), orig, len(orig),
                               ctypes.byref(wrote))
    k32.FreeLibrary(ctypes.c_void_p(hmod))
    os.remove(DST)
    print("restored + unloaded; disk copy removed")
