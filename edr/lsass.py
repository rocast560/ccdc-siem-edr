"""LSASS handle sweep: flag processes holding read/dup handles to LSASS.

Uses NtQuerySystemInformation(SystemExtendedHandleInformation) via ctypes:
every handle in the system with (object, pid, handle, granted access). Entries
whose access mask includes VM_READ / VM_OPERATION / DUP_HANDLE are duplicated
into our process; if the target is lsass.exe, that's the exact prerequisite
for mimikatz / comsvcs MiniDump / procdump -ma credential theft.
"""
import ctypes, json, struct, subprocess, os
from . import state, rules

SystemExtendedHandleInformation = 64
STATUS_INFO_LEN_MISMATCH = 0xC0000004
PROCESS_DUP_HANDLE = 0x40

_ntdll = ctypes.windll.ntdll
_kernel32 = ctypes.windll.kernel32
# x64 handles are pointer-sized; ctypes' default c_int return truncates them,
# which silently breaks every handle API below.
_kernel32.GetCurrentProcess.restype = ctypes.c_void_p
_kernel32.OpenProcess.restype = ctypes.c_void_p
_kernel32.GetProcessId.restype = ctypes.c_ulong
_kernel32.GetProcessId.argtypes = [ctypes.c_void_p]
_kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
_kernel32.DuplicateHandle.restype = ctypes.c_int
_kernel32.DuplicateHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong,
                                      ctypes.c_int, ctypes.c_ulong]
_flagged = set()

ALLOWED_NAMES = {"msmpeng.exe", "nissonsv.exe", "securityhealthservice.exe", "sense.exe",
                 "mpcopyaccelerator.exe"}
ALLOWED_PREFIXES = ("c:\\program files\\windows defender", "c:\\windows\\system32\\")

def _lsass_pid():
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          "(Get-Process lsass -ErrorAction SilentlyContinue).Id"],
                         capture_output=True, text=True, errors="replace", timeout=30).stdout.strip()
    try:
        return int(out)
    except ValueError:
        return None

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
        status = _ntdll.NtQuerySystemInformation(SystemExtendedHandleInformation,
                                                 buf, size, ctypes.byref(needed))
        if status == 0:
            return buf.raw
        if (status & 0xFFFFFFFF) == STATUS_INFO_LEN_MISMATCH or needed.value > size:
            size = needed.value or size * 2
            continue
        return None
    return None

# SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, 40-byte stride after a 16-byte header:
#   +0 PVOID object, +8 ULONG_PTR pid, +16 ULONG_PTR handle, +24 ULONG access,
#   +28 USHORT backtrace, +30 UCHAR ObjectTypeIndex, +31 UCHAR attributes
PROCESS_QUERY_LIMITED = 0x1000

def _process_type_index(raw, count, pid, handle):
    """Discover the ObjectTypeIndex for Process objects by locating a handle
    we know belongs to a process (one we opened ourselves)."""
    for i in range(count):
        off = 16 + i * 40
        if off + 40 > len(raw):
            break
        if struct.unpack_from("<Q", raw, off + 8)[0] == pid and \
           struct.unpack_from("<Q", raw, off + 16)[0] == handle:
            return struct.unpack_from("<B", raw, off + 30)[0]
    return None

def sweep():
    lsapid = _lsass_pid()
    if not lsapid:
        return []
    raw = _handle_table()
    if not raw:
        return []
    count = struct.unpack_from("<Q", raw, 0)[0]
    me = _kernel32.GetCurrentProcess()
    mypid = os.getpid()
    # learn the Process object type index from a handle we just opened
    own = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED, False, mypid)
    ptype = _process_type_index(raw, count, mypid, own) if own else None
    if own:
        _kernel32.CloseHandle(own)
    hits = []
    checked = 0
    for i in range(count):
        off = 16 + i * 40
        if off + 40 > len(raw):
            break
        pid = struct.unpack_from("<Q", raw, off + 8)[0]
        handle = struct.unpack_from("<Q", raw, off + 16)[0]
        access = struct.unpack_from("<I", raw, off + 24)[0]
        if ptype is not None and struct.unpack_from("<B", raw, off + 30)[0] != ptype:
            continue                    # not a process handle - skip cheaply
        if pid in (0, 4, lsapid, mypid) or pid in _flagged or pid > 0xFFFF:
            continue
        if not (access & (0x10 | 0x40 | 0x8)):
            continue
        checked += 1
        owner = _kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if not owner:
            continue
        dup = ctypes.c_void_p()
        found = False
        # duplicate with fresh QUERY access (the original's VM_READ-only access
        # cannot be queried for its target pid)
        if _kernel32.DuplicateHandle(owner, ctypes.c_void_p(handle), me, ctypes.byref(dup),
                                     0x1000, False, 0):
            found = _kernel32.GetProcessId(dup) == lsapid
            _kernel32.CloseHandle(dup)
        _kernel32.CloseHandle(owner)
        if not found:
            continue
        name, path = _pid_image(pid)
        if name.lower() in ALLOWED_NAMES or (path or "").lower().startswith(ALLOWED_PREFIXES):
            continue
        _flagged.add(pid)
        rec = state.norm_event("lsass", "process", "critical",
                               "Process holding LSASS handle: %s (pid %d)" % (name, pid),
                               {"cmdline": path or name, "pid": pid, "access": hex(access)})
        rules.evaluate(rec)
        state.raise_alert("LSASS-HANDLE", "critical",
                          "Handle to LSASS held by %s (pid %d)" % (name, pid),
                          "Credential-theft prerequisite: this process holds a handle to lsass.exe "
                          "with memory-read/duplicate rights - the exact access mimikatz, "
                          "comsvcs MiniDump and procdump -ma require. No benign user process "
                          "needs this.",
                          event=rec, data={"pid": pid, "path": path})
        hits.append((pid, name, access))
    return hits
