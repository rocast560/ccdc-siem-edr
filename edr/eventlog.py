"""Windows built-in monitoring: Security / System / PowerShell / Sysmon event channels.

Consumes the OS's own kernel-sourced telemetry:
- Security 4688 (process creation w/ command line, when audit policy on)
- Security 4698/4702 (scheduled tasks), 4720 (user creation), 1102 (log cleared)
- System 7045 (service install), 7040 (service start-mode change)
- PowerShell 4104 (script block logging)
- Sysmon (Microsoft Sysinternals, if installed) 1/3/7/8/11 etc.

Kernel-level note: real kernel callbacks need a driver; on Windows the practical
built-ins are (a) the Security audit log fed by the kernel, and (b) ETW. sensor.py
also attempts to start an ETW kernel trace via logman and records whether it is live.
"""
import subprocess, time, re, json
from . import state, rules

BOOKMARK = os.path.join(os.path.dirname(__file__), "state", "eventlog-bookmark.json") if (os := __import__("os")) else None

CHANNELS = [
    ("Security", "*[System[(EventID=4688 or EventID=4698 or EventID=4702 or EventID=4720 or EventID=1102 or EventID=4732 or EventID=4769)]]"),
    ("System", "*[System[(EventID=7045 or EventID=7040)]]"),
    ("Windows PowerShell", "*[System[EventID=4104]]"),
    ("Microsoft-Windows-PowerShell/Operational", "*[System[EventID=4104]]"),
    ("Microsoft-Windows-DNS-Client/Operational", "*[System[(EventID=3006 or EventID=3008)]]"),
    ("Microsoft-Windows-Sysmon/Operational", "*"),
]

# we render every record with <time> <eid> and a couple of fields, then parse
XPATH_TIME = re.compile(r"<TimeCreated SystemTime='([^']+)'")
XPATH_EID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
XPATH_COMPUTER = re.compile(r"<Computer>([^<]+)</Computer>")

BOOKMARKS = {}

def _load_bookmarks():
    global BOOKMARKS
    try:
        with open(BOOKMARK) as f:
            BOOKMARKS = json.load(f)
    except Exception:
        BOOKMARKS = {}

def _save_bookmarks():
    try:
        os.makedirs(os.path.dirname(BOOKMARK), exist_ok=True)
        with open(BOOKMARK, "w") as f:
            json.dump(BOOKMARKS, f)
    except Exception:
        pass

def _render(channel, xpath, bookmark=None):
    cmd = ["wevtutil", "qe", channel, "/q:" + xpath, "/c:2000", "/rd:true", "/e:Events", "/f:xml"]
    # note: /bm: needs a bookmark FILE; we instead track the last seen
    # EventRecordID ourselves and filter parsed events against it.
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=120)
    return r.stdout or ""

def _parse(xml):
    """Split the <Events> wrapper into individual <Event> XML strings."""
    return re.findall(r"<Event xmlns='[^']+'>.*?</Event>", xml, re.S)

def _field(ev, tag):
    m = re.search(r"<Data Name='%s'>([^<]*)</Data>" % tag, ev)
    return m.group(1) if m else ""

def poll_channels():
    """Pull new records from each channel; emit normalized events + rule evaluation."""
    if not BOOKMARKS and os.path.isfile(BOOKMARK):
        _load_bookmarks()
    emitted = 0
    for channel, xpath in CHANNELS:
        xml = ""
        try:
            bm = BOOKMARKS.get(channel)
            xml = _render(channel, xpath, bm)
        except Exception:
            continue
        evs = _parse(xml)
        # rd:true renders newest first; walk oldest-first, skip already-seen records
        kept = []
        for ev in evs:
            m_rid = re.search(r"<EventRecordID>(\d+)</EventRecordID>", ev)
            rid = int(m_rrid.group(1)) if (m_rrid := m_rid) else 0
            if bm is not None and rid <= bm:
                continue
            kept.append((rid, ev))
        maxrid = bm or 0
        for rid, ev in reversed(kept):   # oldest first
            m_id = XPATH_EID.search(ev)
            m_t = XPATH_TIME.search(ev)
            eid = m_id.group(1) if m_id else "?"
            ts = m_t.group(1) if m_t else ""
            maxrid = max(maxrid, rid)
            if channel == "Security" and eid == "1102":
                state.norm_event("eventlog", "eventlog", "critical", "Security audit log cleared",
                                 {"eid": eid, "channel": channel})
            if channel.startswith(("Windows PowerShell", "Microsoft-Windows-PowerShell")) and eid == "4104":
                script = _field(ev, "ScriptBlockText")[:300]
                rec = state.norm_event("eventlog", "eventlog", "low",
                                       "PowerShell script block", {"eid": eid, "channel": channel,
                                                                   "cmdline": script})
                rules.evaluate(rec)
            elif channel == "Security" and eid == "4769":
                # Kerberoasting: service ticket requested with RC4 (0x17)
                tkt = _field(ev, "TicketEncryptionType")
                svc = _field(ev, "ServiceName")
                rec = state.norm_event("eventlog", "eventlog",
                                       "high" if tkt == "0x17" else "info",
                                       "Kerberos service ticket: " + (svc or "?"),
                                       {"eid": eid, "channel": channel, "cmdline": svc,
                                        "path": svc, "enc": tkt})
                if tkt == "0x17":
                    state.raise_alert(
                        "KRB-ROAST", "high", "RC4 service ticket requested: " + (svc or "?"),
                        "Kerberos TGS request with RC4 encryption (0x17) - the Kerberoasting "
                        "signature (Rubeus / GetUserSPNs request crackable RC4 tickets for "
                        "offline password attacks). Service: " + (svc or "?"),
                        event=rec, data={"service": svc})
                rules.evaluate(rec)
            elif channel.endswith("DNS-Client/Operational"):
                qname = _field(ev, "QueryName")
                pid = _field(ev, "ProcessID") or _field(ev, "Pid") or "0"
                if qname:
                    try:
                        from . import dnsbeacon
                        v = int(pid, 16) if pid.lower().startswith("0x") else int(pid)
                        dnsbeacon.note_query(v, qname)
                    except (ValueError, ImportError):
                        pass
            elif channel == "Security" and eid == "4688":
                cmdline = _field(ev, "CommandLine")
                newproc = _field(ev, "NewProcessName")
                if "Get-CimInstance Win32_Process" in cmdline:
                    continue          # our own WMI poll subprocess
                rec = state.norm_event("eventlog", "eventlog", "info",
                                       "Process creation (4688): " + newproc,
                                       {"eid": eid, "channel": channel, "cmdline": cmdline,
                                        "path": newproc, "pid": _field(ev, "NewProcessId")})
                rules.evaluate(rec)
                # kernel-fed launch view: scan the image even if the process dies
                # before the next WMI poll (catches instant-exit stagers)
                pl = (newproc or "").lower()
                userdirs = [os.environ.get("TEMP", "").lower(), os.environ.get("APPDATA", "").lower(),
                            "c:\\users\\public", os.environ.get("PROGRAMDATA", "").lower()]
                if pl and any(pl.startswith(u) for u in userdirs if u):
                    from . import signatures
                    hits = signatures.scan_process_image(newproc)
                    if hits:
                        rec2 = state.norm_event("process", "process", "critical",
                                                "Signature hit on launched image (4688): " + newproc,
                                                {"pid": _field(ev, "NewProcessId"), "cmdline": cmdline,
                                                 "path": newproc,
                                                 "sig": ",".join(h["id"] for h in hits)})
                        rules.evaluate(rec2)
            else:
                sev = "high" if eid in ("7045", "4698", "4720", "4732") else "medium"
                rec = state.norm_event("eventlog", "eventlog", sev,
                                       f"{channel} event {eid}",
                                       {"eid": eid, "channel": channel,
                                        "path": _field(ev, "ServiceName") or _field(ev, "TaskName") or channel,
                                        "cmdline": _field(ev, "ImagePath") or ""})
                rules.evaluate(rec)
            emitted += 1
            state.stats["eventlog_records"] += 1
        if maxrid > (bm or 0):
            BOOKMARKS[channel] = maxrid
    if BOOKMARKS:
        _save_bookmarks()
    return emitted

def enable_audit_sources():
    """Turn on Windows built-in monitoring we can rely on. Best-effort."""
    results = {}
    try:
        r = subprocess.run(["auditpol", "/set", "/subcategory:Process Creation", "/success:enable"],
                           capture_output=True, text=True, errors="replace", timeout=60)
        results["auditpol_process_creation"] = (r.returncode == 0)
    except Exception as e:
        results["auditpol_process_creation"] = str(e)
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
                           0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "ProcessCreationIncludeCmdLine_Enabled", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(k)
        results["cmdline_in_4688"] = True
    except Exception as e:
        results["cmdline_in_4688"] = str(e)
    try:
        subprocess.run(["wevtutil", "sl", "Microsoft-Windows-DNS-Client/Operational",
                        "/e:true"], capture_output=True, timeout=30)
        results["dns_client_channel"] = True
    except Exception as e:
        results["dns_client_channel"] = str(e)
    return results

def try_kernel_trace():
    """Attempt a real ETW kernel trace session (kernel-level process/image events).

    Kernel providers can only be hosted by the reserved 'NT Kernel Logger'
    session; flag mask 0x10 = process events. The .etl is flushed continuously
    and retained for forensic analysis (tracerpt converts it to XML); live
    detection additionally rides the kernel-fed Security 4688 channel.
    """
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state", "kernel.etl")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # stop a stale session from a previous run, if any
    subprocess.run(["logman", "stop", "NT Kernel Logger", "-ets"], capture_output=True, timeout=30)
    try:
        r = subprocess.run(
            ["logman", "start", "NT Kernel Logger", "-ets", "-p", "Windows Kernel Trace",
             "0x10", "0xff", "-o", out],
            capture_output=True, text=True, errors="replace", timeout=60)
        if r.returncode == 0:
            state.stats["kernel_trace"] = ("ETW kernel session 'NT Kernel Logger' active "
                                           "(process events, flag 0x10) -> " + out)
            return True
        state.stats["kernel_trace"] = "unavailable: " + (r.stderr or r.stdout).strip()[:160] + \
            " - falling back to Security 4688 audit (kernel-fed event log) + WMI polling"
        return False
    except Exception as e:
        state.stats["kernel_trace"] = "unavailable: " + str(e)[:160]
        return False
