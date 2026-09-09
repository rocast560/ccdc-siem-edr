"""Process sensor: WMI Win32_Process polling + Windows Event Log 4688 enrichment.

Polling gives command lines and parent PIDs without needing a driver; when the
Security audit policy is enabled (see sensor.py setup) event 4688 records are
consumed by eventlog.py for an independent, kernel-sourced view of the same
launches.
"""
import subprocess, json, os, time
from . import state, rules, signatures

_poll = {}    # pid -> record

# parent-child mismatch matrix: host processes that should never spawn these
HOST_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "spoolsv.exe", "explorer.exe",
                "w3wp.exe", "sqlservr.exe", "mysqld.exe", "nginx.exe", "httpd.exe",
                "php-cgi.exe", "tomcat7.exe", "tomcat8.exe", "tomcat9.exe"}
CHILD_INTERPRETERS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
                      "mshta.exe", "certutil.exe", "curl.exe"}

# masquerading: critical system binary names are only legitimate inside Windows
CRITICAL_NAMES = {"svchost.exe", "lsass.exe", "smss.exe", "csrss.exe", "services.exe",
                  "winlogon.exe", "wininit.exe", "dwm.exe", "taskhostw.exe", "conhost.exe",
                  "sihost.exe", "ctfmon.exe", "explorer.exe", "spoolsv.exe", " audiodg.exe",
                  "networkd.exe", "MpCmdRun.exe", "MsMpEng.exe"}
USERDIR_PREFIXES = tuple(p.lower() for p in (
    os.environ.get("TEMP", ""), os.environ.get("APPDATA", ""),
    r"c:\users\public", r"c:\windows\temp", os.environ.get("PROGRAMDATA", "")) if p)

def _is_userdir(path):
    pl = (path or "").lower()
    return any(pl.startswith(u) for u in USERDIR_PREFIXES)

def _check_masquerade(rec_data):
    """Critical Windows binary name executing outside Windows directories."""
    name = (rec_data.get("name") or "").lower()
    path = (rec_data.get("path") or "").lower()
    if name in CRITICAL_NAMES and path and not path.startswith(r"c:\windows") \
            and not path.startswith(r"c:\program files"):
        ev = state.norm_event("masq", "process", "critical",
                               "Masqueraded system binary: %s at %s" % (name, path),
                               {"cmdline": rec_data.get("cmdline", ""), "pid": rec_data.get("pid"),
                                "path": rec_data.get("path", ""), "sig": "masq"})
        rules.evaluate(ev)
        state.raise_alert("PROC-MASQ", "critical",
                          "System binary name running outside Windows: %s" % name,
                          "A process named after a critical Windows binary (" + name + ") is "
                          "executing from " + path + " - the inconspicuous-renaming masquerade "
                          "(g++ implants renamed svchost.exe/lsass.exe/networkd in Temp/Public "
                          "are the watershell-on-Windows pattern).",
                          event=ev, data={"pid": rec_data.get("pid"), "path": path,
                                          "cmdline": (rec_data.get("cmdline") or "")[:160]})

def _check_shell_spawner(rec_data):
    """Unknown user-path binary spawning a shell interpreter - the passive
    backdoor's command-execution giveaway."""
    cname = (rec_data.get("name") or "").lower()
    if cname not in CHILD_INTERPRETERS:
        return
    parent = _poll.get(rec_data.get("ppid"))
    if not parent:
        return
    pname = (parent.get("name") or "").lower()
    ppath = parent.get("path") or ""
    if pname in HOST_PARENTS:
        return                      # matrix rule already covers known hosts
    if _is_userdir(ppath):
        ev = state.norm_event("spawn", "process", "critical",
                               "User-path binary spawned %s: %s" % (cname, ppath),
                               {"cmdline": rec_data.get("cmdline", ""), "pid": rec_data.get("pid"),
                                "path": rec_data.get("path", ""), "ppid": rec_data.get("ppid")})
        state.raise_alert("SPAWN-SHELL", "critical",
                          "%s spawned by unknown user-path binary (%s)" % (cname, pname),
                          "A command interpreter was spawned by a binary running from a "
                          "user-writable directory - the shell-spawner signature of a passive "
                          "backdoor (watershell-class implants pipe network commands straight "
                          "into cmd/powershell children).",
                          event=ev, data={"parent": ppath, "child": cname,
                                          "cmdline": (rec_data.get("cmdline") or "")[:160]})

def _check_parent_chain(rec_data):
    ppid = rec_data.get("ppid")
    parent = _poll.get(ppid)
    if not parent:
        return
    pname = (parent.get("name") or "").lower()
    cname = (rec_data.get("name") or "").lower()
    if pname in HOST_PARENTS and cname in CHILD_INTERPRETERS:
        ev = state.norm_event("procchain", "process", "critical",
                              "Parent-child mismatch: %s spawned %s" % (pname, cname),
                              {"cmdline": rec_data.get("cmdline", ""), "pid": rec_data.get("pid"),
                               "path": rec_data.get("path", ""), "ppid": ppid, "parent": pname})
        state.raise_alert("PROC-SUSP-PARENT", "critical",
                          "%s spawned %s (webshell/macro chain)" % (pname, cname),
                          "A host process that serves content (web server w3wp/nginx, database "
                          "sqlservr/mysqld, Office app, spooler) directly spawned a command "
                          "interpreter - the parent-child signature of webshell command "
                          "execution, macro payloads, or service-context implants.",
                          event=ev, data={"parent": pname, "child": cname, "pid": rec_data.get("pid"),
                                          "cmdline": (rec_data.get("cmdline") or "")[:160]})

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
        _check_parent_chain(rec_data)
        _check_masquerade(rec_data)
        _check_shell_spawner(rec_data)
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
