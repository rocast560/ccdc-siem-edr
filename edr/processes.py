"""Process sensor: WMI Win32_Process polling + Windows Event Log 4688 enrichment.

Polling gives command lines and parent PIDs without needing a driver; when the
Security audit policy is enabled (see sensor.py setup) event 4688 records are
consumed by eventlog.py for an independent, kernel-sourced view of the same
launches.
"""
import subprocess, json, os, time
from . import state, rules, signatures

_poll = {}    # pid -> record

def _ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True, errors="replace", timeout=60).stdout

def poll_once():
    out = _ps("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,"
              "CommandLine,ExecutablePath | ConvertTo-Json -Compress")
    try:
        arr = json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        return []
    if isinstance(arr, dict):
        arr = [arr]
    new = []
    seen = set()
    for p in arr:
        pid = p.get("ProcessId")
        seen.add(pid)
        if pid in _poll:
            continue
        cmdline = p.get("CommandLine") or ""
        # don't record our own poll subprocesses (they run every cycle)
        if "Get-CimInstance Win32_Process" in cmdline:
            seen.add(pid)
            continue
        rec_data = {
            "pid": pid,
            "ppid": p.get("ParentProcessId"),
            "name": p.get("Name") or "",
            "cmdline": cmdline,
            "path": p.get("ExecutablePath") or "",
        }
        _poll[pid] = rec_data
        ev = state.norm_event("process", "process", "info",
                              f"Process start: {rec_data['name']} (pid {pid})", rec_data)
        rules.evaluate(ev)
        # on-launch static scan of the image
        userdirs = [os.environ.get("TEMP", "").lower(), os.environ.get("APPDATA", "").lower()]
        pl = rec_data["path"].lower()
        if pl and (any(pl.startswith(u) for u in userdirs if u) or pl.startswith("c:\\users\\public")):
            hits = signatures.scan_process_image(rec_data["path"])
            if hits:
                ev2 = state.norm_event("process", "process", "critical",
                                       f"Signature hit on launched image: {rec_data['name']}",
                                       {"pid": pid, "cmdline": rec_data["cmdline"], "path": rec_data["path"],
                                        "sig": ",".join(h["id"] for h in hits)})
                rules.evaluate(ev2)
        new.append(rec_data)
    for pid in [k for k in _poll if k not in seen]:
        del _poll[pid]
    state.stats["processes_tracked"] = len(_poll)
    return new
