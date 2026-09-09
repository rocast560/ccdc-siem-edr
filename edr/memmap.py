"""Memory-map sensor: region-level injection artifacts.

Covers the memory-anomaly checklist the signature/memory-string scanner
(memscan.py) does not see:

1. UNBACKED-RWX  - private PAGE_EXECUTE_* regions with no file mapping.
   Injected shellcode lives exactly here. JIT hosts (.NET, java) get a small
   allowlist because managed runtimes legitimately allocate private exec.
2. NEW-RWX       - private executable regions that appeared since the previous
   pass (effects-level tracking of VirtualAlloc/VirtualAllocEx/
   NtAllocateVirtualMemory, which user-mode cannot hook without injecting).
3. SYSCALL-STUB  - the syscall instruction (0F 05) inside PRIVATE executable
   memory. Legitimate syscall stubs exist only inside the mapped ntdll image;
   finding one in private memory is the direct/indirect-syscall evasion
   stub (HellsGate/SysWhispers class) fingerprint.
4. HOLLOWED      - the process image's base region is MEM_PRIVATE instead of
   a mapped image (process hollowing artifact: UnmapViewOfSection +
   VirtualAllocEx over the exe's own header).
"""
import ctypes, os, struct
from ctypes import wintypes
from . import state, rules

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = ctypes.c_void_p
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

from .memscan import MEMORY_BASIC_INFORMATION

PROCESS_VM_READ = 0x10
PROCESS_QUERY_INFORMATION = 0x400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
EXEC_PROTECT = (0x10, 0x20, 0x40, 0x80)      # EXECUTE, EXECUTE_READ, EXECUTE_RW, EXECUTE_COPY

SYSCALL_STUB = b"\x0f\x05\xc3"                # syscall ; ret
STUB_WINDOW = b"\x0f\x05"

JIT_HOSTS = {"dotnet.exe", "java.exe", "javaw.exe", "node.exe", "deno.exe", "bun.exe",
             "msbuild.exe", "w3wp.exe", "sqlservr.exe"}

MAX_REGION = 0x100000                          # inspect up to 1 MB per region
_regions = {}       # pid -> {(base, size, prot)}
_alerted = set()

def _alert(rule, sev, title, why, pid, name, path, extra):
    key = (rule, pid, str(extra.get("base", "")))
    if key in _alerted:
        return
    _alerted.add(key)
    rec = state.norm_event("memmap", "process", sev, title,
                           {"cmdline": path or name, "pid": pid, "path": path or name})
    rules.evaluate(rec)
    data = {"pid": pid, "path": path}
    data.update(extra)
    state.raise_alert(rule, sev, title, why, event=rec, data=data)

def scan_process(pid, name, path):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return []
    jit = (name or "").lower() in JIT_HOSTS
    prev = _regions.get(pid, set())
    cur = set()
    findings = []
    try:
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        buf = ctypes.create_string_buffer(0x10000)
        got = ctypes.c_size_t(0)
        while addr < 0x7FFFFFFFFFFF:
            if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            prot = mbi.Protect
            if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and prot in EXEC_PROTECT \
                    and 0 < size <= 0x10000000:
                cur.add((base, size, prot))
                if not jit:
                    extra = {"base": hex(base), "size": size, "protect": hex(prot),
                             "new": (base, size, prot) not in prev}
                    _alert("MEM-RWX-UNBACKED", "critical",
                           "Unbacked executable memory in %s (pid %d) at %s" % (name, pid, hex(base)),
                           "Private PAGE_EXECUTE region with no file mapping - the canonical "
                           "location of injected shellcode. Legitimate code lives in image "
                           "mappings backed by on-disk files; JIT runtimes are allowlisted.",
                           pid, name, path, extra)
                    if (base, size, prot) not in prev:
                        _alert("MEM-RWX-NEW", "critical",
                               "New executable region appeared in %s (pid %d) at %s" % (name, pid, hex(base)),
                               "A private executable region appeared after the previous scan pass "
                               "- the observable effect of VirtualAlloc/VirtualAllocEx/"
                               "NtAllocateVirtualMemory with executable protection, the loader "
                               "allocation primitive (tracked at effects level because user-mode "
                               "EDRs cannot hook the allocation APIs without injecting).",
                               pid, name, path, extra)
                # syscall-stub scan inside the region
                ofs = 0
                while ofs < min(size, MAX_REGION):
                    n = min(0x10000, size - ofs)
                    if k32.ReadProcessMemory(h, ctypes.c_void_p(base + ofs), buf, n,
                                             ctypes.byref(got)) and got.value > 2:
                        chunk = buf.raw[:got.value]
                        i = chunk.find(SYSCALL_STUB)
                        if i == -1:
                            j = chunk.find(STUB_WINDOW)
                            if j != -1 and chunk[j:j + 8].count(b"\xc3"):
                                i = j
                        if i != -1:
                            _alert("SYSCALL-STUB", "critical",
                                   "Syscall stub in private memory: %s (pid %d) at %s" % (name, pid, hex(base + ofs + i)),
                                   "The syscall instruction (0F 05) executes inside PRIVATE "
                                   "executable memory. Legitimate syscall stubs exist only in the "
                                   "mapped ntdll image - this is a direct/indirect syscall stub "
                                   "(HellsGate / HalosGate / SysWhispers), the API-hook evasion "
                                   "used by Havoc Demon and BOF loaders.",
                                   pid, name, path,
                                   {"base": hex(base + ofs + i), "size": size, "protect": hex(prot)})
                            break
                    ofs += n
            addr = base + size
        # hollowed-image check: the exe's own base should be a mapped image
        if path and os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    pe_off = struct.unpack_from("<I", f.read(0x40), 0x3C)[0]
                    f.seek(pe_off + 24 + 20)
                    imgbase = struct.unpack("<Q", f.read(8))[0]
            except (OSError, struct.error):
                imgbase = 0x140000000
            mbi2 = MEMORY_BASIC_INFORMATION()
            if k32.VirtualQueryEx(h, ctypes.c_void_p(imgbase), ctypes.byref(mbi2), ctypes.sizeof(mbi2)) \
                    and mbi2.Type == MEM_PRIVATE and mbi2.State == MEM_COMMIT:
                _alert("MEM-HOLLOWED", "critical",
                       "Hollowed process image: %s (pid %d)" % (name, pid),
                       "The process's own image base is private committed memory instead of a "
                       "mapped image file - the process-hollowing artifact (UnmapViewOfSection "
                       "of the original exe, then allocation of replacement payload over it).",
                       pid, name, path, {"base": hex(imgbase), "size": mbi2.RegionSize or 0})
    finally:
        k32.CloseHandle(h)
    _regions[pid] = cur
    return findings

def poll(limit=6, candidates=None):
    if candidates is None:
        from . import modules as _mods
        candidates = [p for p in _mods._processes()
                      if not (p[2] or "").lower().startswith(r"c:\windows")][:24]
    done = 0
    for pid, name, path, *_ in candidates:
        if done >= limit:
            break
        scan_process(pid, name, path)
        done += 1
    return done
