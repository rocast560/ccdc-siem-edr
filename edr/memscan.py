"""Process memory scanner: signature rules applied to committed memory.

Walks each candidate process's address space with VirtualQueryEx and
ReadProcessMemory, scanning committed private/RWX regions for the same
signature packs used on disk. imix does not sleep-encrypt its memory, so its
compiled-in config surface (IMIX_* strings, eldritch/tavern markers) is
findable here even when the on-disk image was deleted after launch.

Candidates: processes whose image lives in user-writable paths, plus anything
already carrying a signature alert. System/EDR processes are skipped.
"""
import ctypes, os, struct, subprocess, json
from ctypes import wintypes
from . import state, rules, signatures

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = ctypes.c_void_p
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

PROCESS_VM_READ = 0x10
PROCESS_QUERY_INFORMATION = 0x400
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_NOACCESS = 0x01
SCANNABLE = (PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, 0x02, 0x20, 0x40, 0x80)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD), ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)]

MAX_REGION = 1 * 1024 * 1024      # read chunks of 1 MB
PER_PROCESS_BUDGET = 8 * 1024 * 1024    # bytes scanned per process per pass
PER_CYCLE_PROCS = 4                # candidates per cycle; remainder rotate next pass
_scanned_pids = set()
_cursor = 0

USER_PREFIXES = [p.lower() for p in (
    os.environ.get("TEMP", ""), os.environ.get("APPDATA", ""),
    r"c:\users\public", os.environ.get("PROGRAMDATA", "")) if p]
SKIP_PREFIXES = (r"c:\windows", r"c:\program files")

def _candidate_processes():
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CreationDate "
                          "| ConvertTo-Json -Compress"],
                         capture_output=True, text=True, errors="replace", timeout=90).stdout
    try:
        arr = json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        return []
    if isinstance(arr, dict):
        arr = [arr]
    cands = []
    for p in arr:
        path = (p.get("ExecutablePath") or "").lower()
        if not path:
            continue
        if any(path.startswith(s) for s in SKIP_PREFIXES):
            continue
        # anything running outside Windows/Program Files is a scan candidate:
        # user-writable launch paths AND interpreter hosts of file-less code
        cands.append((p["ProcessId"], p.get("Name") or "?", p.get("ExecutablePath"),
                      p.get("CreationDate") or ""))
    # newest processes first - fresh launches are the highest-signal targets
    cands.sort(key=lambda c: c[3], reverse=True)
    return [(pid, name, path) for pid, name, path, _ in cands]

def scan_process(pid, name, path, force=False):
    """Scan one process's committed memory; alert on signature hits.
    force=True bypasses the already-scanned cache (on-demand console scans:
    the awake-vs-asleep sleep-encryption exercise needs repeated scans)."""
    if (pid in _scanned_pids and not force) or pid == os.getpid():
        return []
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return []
    hits = []
    budget = PER_PROCESS_BUDGET
    try:
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        buf = ctypes.create_string_buffer(MAX_REGION)
        got = ctypes.c_size_t(0)
        while addr < 0x7FFFFFFFFFFF and budget > 0:
            if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0            # c_void_p yields None for address 0
            size = mbi.RegionSize or 0
            if mbi.State == MEM_COMMIT and mbi.Protect in SCANNABLE and \
                    mbi.Protect != PAGE_NOACCESS and 0 < size <= MAX_REGION * 4:
                ofs = 0
                while ofs < size and budget > 0:
                    n = min(MAX_REGION, size - ofs)
                    if k32.ReadProcessMemory(h, ctypes.c_void_p(base + ofs),
                                             buf, n, ctypes.byref(got)) and got.value:
                        found = signatures.scan_bytes(buf.raw[:got.value], memory=True)
                        for f in found:
                            if f["id"] not in [x[0] for x in hits]:
                                hits.append((f["id"], hex(base + ofs)))
                        budget -= got.value
                    ofs += n
            if hits:
                break
            addr = base + size
    finally:
        k32.CloseHandle(h)
    if hits:
        _scanned_pids.add(pid)
        for sig_id, where in hits:
            rec = state.norm_event("memscan", "process", "critical",
                                   "Signature in memory: %s in %s (pid %d)" % (sig_id, name, pid),
                                   {"cmdline": path or name, "pid": pid, "sig": sig_id,
                                    "address": where})
            rules.evaluate(rec)
            state.raise_alert("MEM-" + sig_id, "critical",
                              "In-memory implant signature: %s in %s (pid %d)" % (sig_id, name, pid),
                              "Process memory scan matched the '%s' signature pack inside a "
                              "committed region of this process. The imix implant does not "
                              "sleep-encrypt its memory, so its compiled-in config surface is "
                              "directly readable even after the on-disk image is deleted - "
                              "this catches running implants the file scanner can no longer see." % sig_id,
                              event=rec, data={"pid": pid, "path": path, "address": where})
    return hits

def scan_all():
    global _cursor
    hits = []
    cands = _candidate_processes()
    if not cands:
        return hits
    _cursor %= len(cands)
    batch = (cands[_cursor:] + cands[:_cursor])[:PER_CYCLE_PROCS]
    _cursor = (_cursor + PER_CYCLE_PROCS) % max(len(cands), 1)
    for pid, name, path in batch:
        found = scan_process(pid, name, path)
        if found:
            hits.append((pid, name, found))
    return hits
