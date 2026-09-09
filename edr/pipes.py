"""Named-pipe sensor: C2 SMB-pipe posture detection.

Enumerates the pipe namespace via FindFirstFile and flags:
- pipes matching known C2 naming (Cobalt Strike msagent_/postex_ etc)
- pipes whose server process runs from a user-writable path (an implant
  hosting a pipe for lateral chaining - the imix/Beacon SMB transport)
- new pipes after baseline (diff), so anything novel surfaces
"""
import os, ctypes, subprocess, json, string, re
from . import state

_allowed_rx = re.compile(r"^(chrome|mojo|slack|discord|teams|ms-|wininit|lsass|ntsvcs|scerpc|"
                         r"eventlog|SessEnvPublic|ROUTER|WKSSPC|atsvc|W32TIME|epmapper|LSM_API|"
                         r"SQLLocal|MySQL|postgresql|docker|vsock|dockerDesktop)", re.I)

KNOWN_C2_RX = re.compile(r"msagent_|postex_|\\mssql_|demon|havoc|imix|realm|chrome_8080", re.I)

_baseline = None
_alerted = set()

def _list_pipes():
    # listing \\.\pipe\ via FindFirstFile through ctypes
    k32 = ctypes.windll.kernel32
    class WIN32_FIND_DATAW(ctypes.Structure):
        # FILETIMEs as paired uint32s: c_uint64 would 8-byte-align and shift
        # cFileName, truncating the first two characters of every name
        _fields_ = [("dwFileAttributes", ctypes.c_uint32),
                    ("ftCreationTimeLo", ctypes.c_uint32), ("ftCreationTimeHi", ctypes.c_uint32),
                    ("ftLastAccessLo", ctypes.c_uint32), ("ftLastAccessHi", ctypes.c_uint32),
                    ("ftLastWriteLo", ctypes.c_uint32), ("ftLastWriteHi", ctypes.c_uint32),
                    ("nFileSizeHigh", ctypes.c_uint32), ("nFileSizeLow", ctypes.c_uint32),
                    ("dwReserved0", ctypes.c_uint32), ("dwReserved1", ctypes.c_uint32),
                    ("cFileName", ctypes.c_wchar * 260), ("cAlternateFileName", ctypes.c_wchar * 14)]
    fd = WIN32_FIND_DATAW()
    k32.FindFirstFileW.restype = ctypes.c_void_p
    k32.FindNextFileW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k32.FindClose.argtypes = [ctypes.c_void_p]
    h = k32.FindFirstFileW("\\\\.\\pipe\\*", ctypes.byref(fd))
    if not h or h == 0xFFFFFFFFFFFFFFFF:
        return []
    names = []
    try:
        while True:
            names.append(fd.cFileName)
            if not k32.FindNextFileW(h, ctypes.byref(fd)):
                break
    finally:
        k32.FindClose(h)
    return names

def _pipe_server(name):
    """Best-effort: GetNamedPipeServerProcessId via ctypes."""
    try:
        k32 = ctypes.windll.kernel32
        h = k32.CreateFileW("\\\\.\\pipe\\" + name, 0x80000000, 0, None, 3, 0, None)  # OPEN_EXISTING
        if h == -1 or h == 0xFFFFFFFFFFFFFFFF:
            return None
        try:
            pid = ctypes.c_uint32()
            if k32.GetNamedPipeServerProcessId(h, ctypes.byref(pid)):
                return pid.value
        finally:
            k32.CloseHandle(ctypes.c_void_p(h))
    except Exception:
        pass
    return None

def _pid_path(pid):
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          "Get-CimInstance Win32_Process -Filter 'ProcessId=%d' | "
                          "Select-Object Name,ExecutablePath | ConvertTo-Json -Compress" % pid],
                         capture_output=True, text=True, errors="replace", timeout=30).stdout
    try:
        j = json.loads(out) if out.strip() else None
        return (j or {}).get("ExecutablePath") or ""
    except Exception:
        return ""

def poll():
    global _baseline
    names = _list_pipes()
    if _baseline is None:
        _baseline = set(names)
        return []
    findings = []
    cur = set(names)
    for n in names:
        if KNOWN_C2_RX.search(n):
            if ("c2", n) not in _alerted:
                _alerted.add(("c2", n))
                rec = state.norm_event("pipes", "network", "critical",
                                       "C2-named pipe: " + n, {"peer": n, "path": n})
                state.raise_alert("NET-PIPE", "critical", "C2 named pipe: " + n,
                    "Pipe name matches known command-and-control naming (Cobalt Strike "
                    "msagent_/postex_, Havoc Demon, Realm). SMB-pipe C2 channels look like "
                    "this - no network socket involved.",
                    event=rec, data={"pipe": n})
            findings.append(n)
            continue
        if n in _baseline or _allowed_rx.match(n) or ("new", n) in _alerted:
            continue
        _alerted.add(("new", n))
        spid = _pipe_server(n)
        path = _pid_path(spid) if spid else ""
        if path and not path.lower().startswith((r"c:\windows", r"c:\program files")):
            rec = state.norm_event("pipes", "network", "high",
                                   "New pipe hosted by user-path process: %s (%s)" % (n, path),
                                   {"peer": n, "path": path, "pid": spid})
            state.raise_alert("NET-PIPE", "high", "Implant-hosted pipe: " + n,
                "A pipe that appeared after baseline is hosted by a process running from a "
                "user-writable path - the inverted SMB-pipe C2 posture used for lateral "
                "chaining (imix tcp_bind/pipe chaining, Beacon SMB).",
                event=rec, data={"pipe": n, "pid": spid, "path": path})
            findings.append(n)
    _baseline |= cur
    return findings
