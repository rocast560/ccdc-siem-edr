"""Cross-process handle sensor: the process-meddling API observable.

User-mode EDRs cannot hook OpenProcess across the system, but the RESULT of a
privileged open is visible in the system handle table: a process holding a
handle to ANOTHER process with PROCESS_VM_WRITE / PROCESS_CREATE_THREAD /
PROCESS_VM_OPERATION is the prerequisite posture for WriteProcessMemory +
CreateRemoteThread injection. (VM_READ on lsass specifically is handled by
lsass.py; this sensor covers every other cross-process combination.)

Excludes: our own sensor process, Defender components, and read-only handles
(they'd flood on management tooling).
"""
import ctypes, os, struct, subprocess, json
from . import state, rules

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.GetProcessId.restype = ctypes.c_ulong
k32.GetProcessId.argtypes = [ctypes.c_void_p]
k32.DuplicateHandle.restype = ctypes.c_int
k32.DuplicateHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong,
                                ctypes.c_int, ctypes.c_ulong]
ntdll = ctypes.windll.ntdll

import os as _os
_DBG = bool(_os.environ.get("EDR_DEBUG"))
SystemExtendedHandleInformation = 64
PROCESS_DUP_HANDLE = 0x40
PROCESS_VM_WRITE = 0x20
PROCESS_CREATE_THREAD = 0x02
PROCESS_VM_OPERATION = 0x08
MEDDLING = PROCESS_VM_WRITE | PROCESS_CREATE_THREAD

ALLOWED_NAMES = {"msmpeng.exe", "nissonsv.exe", "securityhealthservice.exe", "sense.exe",
                 "mpcopyaccelerator.exe"}
ALLOWED_PREFIXES = ("c:\\program files\\windows defender", "c:\\windows\\system32\\",
                    "c:\\program files\\", "c:\\program files (x86)\\", "\\\\?\\c:\\windows\\")
# per-user install locations match as infixes (they sit mid-path)
ALLOWED_INFIXES = ("\\appdata\\local\\microsoft\\", "\\appdata\\local\\programs\\")

def _trusted_image(path):
    pl = (path or "").lower()
    return pl.startswith(ALLOWED_PREFIXES) or any(p in pl for p in ALLOWED_INFIXES)
_flagged = set()

def _pid_image(pid):
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          "Get-CimInstance Win32_Process -Filter 'ProcessId=%d' | "
                          "Select-Object Name,ExecutablePath | ConvertTo-Json -Compress" % pid],
                         capture_output=True, text=True, errors="replace", timeout=30).stdout
    try:
        j = json.loads(out) if out.strip() else None
        return (j or {}).get("Name", "?"), (j or {}).get("ExecutablePath") or ""
    except Exception:
        return "?", ""

def _handle_table():
    size = 0x400000
    for _ in range(6):
        buf = ctypes.create_string_buffer(size)
        needed = ctypes.c_ulong(0)
        st = ntdll.NtQuerySystemInformation(SystemExtendedHandleInformation,
                                            buf, size, ctypes.byref(needed))
        if st == 0:
            return buf.raw
        if (st & 0xFFFFFFFF) == 0xC0000004 or needed.value > size:
            size = needed.value or size * 2
            continue
        return None
    return None

def sweep(limit_per_owner=4):
    me = k32.GetCurrentProcess()
    mypid = os.getpid()
    hits = []
    per_owner = {}
    from . import lsass as _lsass
    # learn the Process object type index from a handle we opened on ourselves.
    # The handle must exist BEFORE the snapshot, and its type is verified by
    # querying the duplicated target - a stale/recycled handle value would
    # otherwise poison the type filter and silently drop every entry.
    own = k32.OpenProcess(0x1000, False, mypid)
    raw = _handle_table()
    if not raw:
        if own:
            k32.CloseHandle(own)
        return []
    count = struct.unpack_from("<Q", raw, 0)[0]
    ptype = None
    if own:
        # verify: duplicating 'own' must yield OUR pid - else the value was recycled
        try:
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            dup = ctypes.c_void_p()
            if k32.DuplicateHandle(k32.GetCurrentProcess(), ctypes.c_void_p(own),
                                   k32.GetCurrentProcess(), ctypes.byref(dup), 0x1000, False, 0):
                if k32.GetProcessId(dup) == mypid:
                    ptype = _lsass._process_type_index(raw, count, mypid, own)
                k32.CloseHandle(dup)
        except Exception:
            ptype = None
        finally:
            k32.CloseHandle(own)
    import os as _os
    if _os.environ.get("EDR_DEBUG"):
        from . import state as _st
        type_match = sum(1 for i in range(min(count, 50000))
                         if struct.unpack_from("<B", raw, 16 + i * 40 + 30)[0] == ptype) \
            if ptype is not None else -1
        _st.norm_event("dbg", "audit", "info", "handles-sweep diag",
                       {"count": count, "ptype": ptype, "type_matches_first50k": type_match,
                        "raw_len": len(raw)})
    if ptype is None:
        # without the type filter every file/key row with VM-ish access masks
        # would need expensive duplication and the sweep overruns its cadence;
        # retry next cycle instead
        return []
    for i in range(count):
        off = 16 + i * 40
        if off + 40 > len(raw):
            break
        pid = struct.unpack_from("<Q", raw, off + 8)[0]
        handle = struct.unpack_from("<Q", raw, off + 16)[0]
        access = struct.unpack_from("<I", raw, off + 24)[0]
        if pid in (0, 4, mypid) or pid in _flagged or pid > 0xFFFF:
            continue
        if not (access & MEDDLING):
            continue
        if per_owner.get(pid, 0) >= limit_per_owner:
            continue
        if ptype is not None and \
                struct.unpack_from("<B", raw, off + 30)[0] != ptype:
            continue
        owner = k32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if not owner:
            continue
        dup = ctypes.c_void_p()
        found = False
        if k32.DuplicateHandle(owner, ctypes.c_void_p(handle), me, ctypes.byref(dup),
                               0x1000, False, 0):
            target = k32.GetProcessId(dup)
            found = target not in (0, pid)
            if found and _DBG:
                from . import state as _st
                _st.norm_event("dbg", "audit", "info", "handles found-stage",
                               {"pid": pid, "target": target, "access": hex(access)})
            k32.CloseHandle(dup)
        k32.CloseHandle(owner)
        if not found:
            continue
        per_owner[pid] = per_owner.get(pid, 0) + 1
        name, path = _pid_image(pid)
        if name.lower() in ALLOWED_NAMES or _trusted_image(path):
            continue
        _flagged.add(pid)
        rec = state.norm_event("handles", "process", "critical",
                               "Cross-process meddling handle: %s (pid %d)" % (name, pid),
                               {"cmdline": path or name, "pid": pid})
        rules.evaluate(rec)
        state.raise_alert("PROC-XHANDLE", "critical",
                          "%s (pid %d) holds VM_WRITE/CREATE_THREAD handle to another process" % (name, pid),
                          "This process owns a handle to a DIFFERENT process with "
                          "PROCESS_VM_WRITE / PROCESS_CREATE_THREAD rights - the exact "
                          "prerequisite for WriteProcessMemory + CreateRemoteThread injection. "
                          "No benign user process needs write access to another process's memory.",
                          event=rec, data={"pid": pid, "path": path, "access": hex(access)})
        hits.append((pid, name, access))
    return hits
