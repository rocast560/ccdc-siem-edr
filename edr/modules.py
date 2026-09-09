"""Module-walk sensor: per-process loaded-module telemetry via Toolhelp32.

Three detections ride one snapshot pass:
1. SIDELOAD  - a Windows-named DLL (version.dll, winmm.dll, ...) loaded from
   outside System32, or any module loaded from a user-writable path into a
   process whose image is elsewhere -> search-order hijack / proxy DLL.
2. HOOK-DLL  - the same unsigned module loaded into N+ processes is the
   observable fingerprint of a SetWindowsHookEx global hook (keyloggers) or
   broadcast DLL injection: legitimate DLLs don't need to be everywhere.
3. MASQ assist - Defender/binaries expected in service paths running elsewhere.
"""
import ctypes, os, struct, subprocess, json, collections
from ctypes import wintypes
from . import state, rules

k32 = ctypes.windll.kernel32
k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
k32.CloseHandle.argtypes = [ctypes.c_void_p]

TH32CS_SNAPMODULE = 0x8
TH32CS_SNAPMODULE32 = 0x10
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]

# DLLs that should only ever load from System32
WINDOWS_DLLS = {"version.dll", "winmm.dll", "ws2_32.dll", "uxtheme.dll", "dwmapi.dll",
                "mpclient.dll", "mpsvc.dll", "dbgcore.dll", "dbghelp.dll", "ntmarta.dll",
                "cryptsp.dll", "profapi.dll", "netutils.dll", "srvcli.dll", "wkscli.dll"}
SERVICE_IMG = (r"c:\windows", r"c:\program files")
USER_WRITABLE = [p.lower() for p in (os.environ.get("TEMP", ""), os.environ.get("APPDATA", ""),
                                     r"c:\users\public", os.environ.get("PROGRAMDATA", "")) if p]
DEFENDER_NAMES = {"msmpeng.exe", "mpcmdrun.exe", "nis srv.exe", "nissrv.exe"}
HOOK_THRESHOLD = 4          # same unsigned DLL in >= N processes
MODULES_PER_CYCLE = 40      # processes per pass; rotates

_module_pids = {}           # dll path -> set(pids)
_alerted = set()
_cursor = 0

def _processes():
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
    procs = []
    for p in arr:
        if not p.get("ExecutablePath"):
            continue
        procs.append((p["ProcessId"], p.get("Name") or "?", p.get("ExecutablePath"),
                      p.get("CreationDate") or ""))
    procs.sort(key=lambda c: c[3], reverse=True)   # newest first
    return procs

def _modules(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return []
    out = []
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(MODULEENTRY32W)
    try:
        if k32.Module32FirstW(snap, ctypes.byref(me)):
            while True:
                out.append((me.szModule, me.szExePath))    # (name, path)
                me.dwSize = ctypes.sizeof(MODULEENTRY32W)
                if not k32.Module32NextW(snap, ctypes.byref(me)):
                    break
    finally:
        k32.CloseHandle(snap)
    return out

def _alert(rule, sev, title, why, pid, path, extra=None):
    key = (rule, pid, path.lower())
    if key in _alerted:
        return
    _alerted.add(key)
    rec = state.norm_event("modules", "process", sev, title,
                           {"cmdline": path, "pid": pid, "path": path})
    rules.evaluate(rec)
    data = {"pid": pid, "path": path}
    if extra:
        data.update(extra)
    state.raise_alert(rule, sev, title, why, event=rec, data=data)

def poll():
    global _cursor
    procs = _processes()
    if not procs:
        return
    # the sensors' own System32 subprocess churn (powershell/wevtutil/tasklist
    # every few seconds) would flood the batch and starve the processes we
    # actually want to walk - non-Windows processes only, newest first
    nonwin = [p for p in procs if not (p[2] or "").lower().startswith(r"c:\windows")]
    nonwin.sort(key=lambda c: c[3], reverse=True)
    if not nonwin:
        return
    _cursor %= len(nonwin)
    batch = (nonwin[_cursor:] + nonwin[:_cursor])[:MODULES_PER_CYCLE]
    _cursor = (_cursor + MODULES_PER_CYCLE) % len(nonwin)
    for pid, name, path, _ in batch:
        exe_l = (path or "").lower()
        for mod_name, mod_path in _modules(pid):
            mp = (mod_path or "").lower()
            mn = mod_name.lower()
            if not mp:
                continue
            # 1a. Windows-named DLL outside System32
            if mn in WINDOWS_DLLS and not mp.startswith(r"c:\windows\system32") \
                    and mn not in _alerted:
                _alert("MOD-SIDELOAD", "critical",
                       f"{mod_name} loaded from {mp} (pid {pid}, {name})",
                       "A Windows system DLL name is loaded from outside System32. This is the "
                       "DLL search-order hijack / proxy-DLL sideload primitive: a signed host "
                       "loads an attacker-controlled namesake from its own directory. "
                       "(LockBit-style delivery uses exactly this against Defender binaries.)",
                       pid, mod_path, {"module": mod_name})
            # 1b. user-writable module inside a service-path process
            if any(mp.startswith(u) for u in USER_WRITABLE) and \
                    any(exe_l.startswith(s) for s in SERVICE_IMG):
                _alert("MOD-SIDELOAD", "critical",
                       f"User-writable module {mn} inside service process {name} (pid {pid})",
                       "A process running from Windows/Program Files has loaded a module from a "
                       "user-writable directory - injected code inside a trusted host.",
                       pid, mod_path, {"module": mod_name})
            # 2. track unsigned-ish modules across processes (hook DLL correlation)
            if not any(mp.startswith(s) for s in SERVICE_IMG):
                _module_pids.setdefault(mp, set()).add(pid)
    # hook-DLL correlation pass
    from . import tuning
    for mp, pids in _module_pids.items():
        if not tuning.hookdll_is_suspicious(mp):
            continue      # Microsoft-managed / non-writable paths: legit shared DLLs
        if len(pids) >= HOOK_THRESHOLD and ("HOOK-DLL", 0, mp) not in _alerted:
            _alert("HOOK-DLL", "critical",
                   f"Module loaded into {len(pids)} processes: {mp}",
                   "The same non-system module is present in many processes at once - the "
                   "observable fingerprint of a SetWindowsHookEx global hook (keylogger "
                   "persistence) or broadcast DLL injection. Legitimate application DLLs load "
                   "into their own process, not everywhere.",
                   sorted(pids)[-1], mp, {"processes": sorted(pids)[:12], "count": len(pids)})
            _alerted.add(("HOOK-DLL", 0, mp))
    # 3. Defender binaries outside their install path
    for pid, name, path, _ in procs:
        nl = (name or "").lower().replace(" ", "")
        if nl in DEFENDER_NAMES and not (path or "").lower().startswith(
                (r"c:\program files\windows defender", r"c:\windows")):
            _alert("PROC-DEFENDER-SIDELOAD", "critical",
                   f"Defender binary running from {path}",
                   "A Windows Defender executable is running outside its install directory - "
                   "the Defender-sideload evasion variant (signed Defender binary hosting an "
                   "attacker proxy DLL).",
                   pid, path or name)
