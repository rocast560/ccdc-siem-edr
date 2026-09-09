"""Rules engine: Sigma-like rules evaluated against normalized events.

Rule shape:
{
  "id": "PROC-ENC-PS",
  "name": "Encoded PowerShell command line",
  "severity": "high",
  "kind": "process",
  "field": "cmdline",
  "re": "-enc(odedcommand)",
  "why": "why this fired, shown in the console"
}
"""
import re
from . import state

RULES = [
    # ---- process / execution ----
    dict(id="PROC-ENC-PS", name="Encoded PowerShell command line", severity="high", kind="process",
         field="cmdline", re=r"(?i)-e?nc(odedcommand)?\s+[a-z0-9+/=]{16,}",
         why="PowerShell launched with -EncodedCommand. Stagers and droppers use base64 "
             "command lines to defeat casual command-line review and naive string signatures."),
    dict(id="PROC-NOPS-AMSI", name="PowerShell with AMSI/disable flags", severity="high", kind="process",
         field="cmdline", re=r"(?i)(amsi[_-]?init|amsiInitFailed|disable-runtime-monitoring|noprofile.*-noni)",
         why="Command line attempts to disable or sidestep AMSI instrumentation."),
    dict(id="PROC-RUNDLL-NOARG", name="rundll32 with no arguments", severity="medium", kind="process",
         field="cmdline", re=r"(?i)rundll32(\.exe)?\"?\s*$",
         why="Argument-less rundll32 is the classic Cobalt Strike spawn posture: the beacon "
             "injects into the suspended process, so no DLL argument ever appears."),
    dict(id="PROC-LOLBIN-DOWNLOAD", name="LOLBIN network fetch", severity="high", kind="process",
         field="cmdline", re=r"(?i)(certutil(\.exe)?\"?\s+-urlcache|bitsadmin(\.exe)?\"?\s+/transfer|mshta(\.exe)?\"?\s+http|regsvr32(\.exe)?\"?\s+/i:http)",
         why="Signed LOLBIN used to fetch a remote payload - common C2 stager delivery."),
    dict(id="PROC-SUSP-PARENT", name="Service/host process spawning script interpreter", severity="critical", kind="process",
         field="cmdline", re=r"(?i)^(winword|excel|spoolsv|explorer|w3wp|sqlservr|mysqld|nginx|httpd|php-cgi|tomcat\d*|java)\.exe\s+(\S+\s+)*(powershell|cmd|wscript|cscript|rundll32)",
         why="Unexpected parent-child pair: web server (w3wp), database (sqlservr/mysqld), "
             "or document/spooler process launching an interpreter - the signature of webshell "
             "command execution, macro execution, or a service-context implant."),
    dict(id="EVT-SUSP-PARENT", name="Service/host spawning interpreter (4688)", severity="critical", kind="eventlog",
         field="cmdline", re=r"(?i)^(winword|excel|spoolsv|explorer|w3wp|sqlservr|mysqld|nginx|httpd|php-cgi|tomcat\d*|java)\.exe\s+(\S+\s+)*(powershell|cmd|wscript|cscript|rundll32)",
         why="Kernel-fed 4688: web/database/document host process launched a script "
             "interpreter (webshell command execution family)."),
    dict(id="PROG-IMPLANT-LAUNCH", name="Signature hit on launched process image", severity="critical", kind="process",
         field="sig", re=r".", why="Process launched from an image whose bytes matched an implant signature rule."),
    dict(id="PROC-SCRIPTHOST", name="Script host launching from a drop zone", severity="high", kind="process",
         field="cmdline", re=r"(?i)(wscript|cscript|mshta)(\.exe)?\"?\s+.*\\appdata\\|\\users\\public\\|\\temp\\",
         why="Windows Script Host executing content from a user-writable drop zone."),
    dict(id="EVT-SCRIPTHOST", name="Script host launch (4688)", severity="high", kind="eventlog",
         field="cmdline", re=r"(?i)(wscript|cscript|mshta)(\.exe)?\"?\s+.*\\appdata\\|\\users\\public\\|\\temp\\",
         why="Kernel-fed 4688: script host executing drop-zone content - the evasion-script-"
             "host-launcher family (chm/lnk/js/vbs cradles)."),
    dict(id="PROC-DEFENDER-SIDELOAD", name="Defender binary outside install path", severity="critical", kind="process",
         field="cmdline", re=r"(?i)(msmpeng|mpcmdrun|nissrv)(\.exe).*(\\appdata\\|\\users\\public\\|\\temp\\)",
         why="Windows Defender executable running from a user-writable directory - the "
             "Defender-sideload evasion (signed Defender binary hosting a proxy DLL)."),
    dict(id="EVT-DEFENDER-SIDELOAD", name="Defender binary outside install path (4688)", severity="critical", kind="eventlog",
         field="cmdline", re=r"(?i)(msmpeng|mpcmdrun|nissrv)(\.exe).*(\\appdata\\|\\users\\public\\|\\temp\\)",
         why="Kernel-fed 4688: Defender binary launched from a drop zone."),
    dict(id="PROC-MIMIKATZ-CLI", name="Credential-dump tooling command line", severity="critical", kind="process",
         field="cmdline", re=r"(?i)(sekurlsa::logonpasswords|lsadump::sam|procdump.*-ma.*lsass|comsvcs\.dll,MiniDump)",
         why="Command line matches credential-dumping invocation patterns (mimikatz modules, "
             "LSASS minidump via comsvcs or procdump)."),
    dict(id="PROC-SAM-SAVE", name="Registry hive dump (SAM/SYSTEM/SECURITY)", severity="critical", kind="process",
         field="cmdline", re=r"(?i)(reg(\.exe)?\"?\s+save\s+HKLM\\(SAM|SYSTEM|SECURITY)|secretsdump|ntdsutil.*\"ac i n t ds\")",
         why="Extracting the SAM/SYSTEM/SECURITY hives to disk - offline credential extraction "
             "prerequisite (reg save, Impacket secretsdump, ntdsutil)."),
    dict(id="PROC-LOG-CLEAR", name="Event log clearing", severity="critical", kind="process",
         field="cmdline", re=r"(?i)(wevtutil(\.exe)?\"?\s+cl|clear-eventlog|Remove-WinEvent)",
         why="Clearing Windows event logs - classic anti-forensics during an intrusion."),
    dict(id="PROC-AUDIT-DISABLE", name="Security auditing disabled", severity="critical", kind="process",
         field="cmdline", re=r"(?i)auditpol(\.exe)?\"?\s+/set\s+.*(/success:disable|/failure:disable|/clear)",
         why="Disabling audit policy blinds the kernel-fed event sources this EDR relies on."),

    # ---- files ----
    dict(id="FILE-IMPLANT-SIG", name="Implant signature match on file", severity="critical", kind="file",
         field="path", re=r".", why="Static byte-signature pack matched this file on write/scan."),
    dict(id="FILE-WEBROOT-SHELL", name="Webshell-pattern file written", severity="critical", kind="file",
         field="content_sig", re=r"webshell", why="File content matched webshell function patterns."),
    dict(id="FILE-TOME", name="Eldritch tome / C2 script dropped", severity="high", kind="file",
         field="content_sig", re=r"eldritch", why="File content matched Realm imix 'eldritch' tome indicators."),

    # ---- persistence (auditor diffs surface these) ----
    dict(id="PERS-RUNKEY", name="New autorun registry value", severity="high", kind="registry",
         field="path", re=r".", why="Persistence auditor diff: new value in a Run/RunOnce key."),
    dict(id="PERS-SERVICE", name="New service installed", severity="critical", kind="service",
         field="path", re=r".", why="New service registration - check binPath for user-writable "
             "paths or interpreter wrappers."),
    dict(id="PERS-TASK", name="New scheduled task", severity="high", kind="task",
         field="path", re=r".", why="New scheduled task - common CCDC red-team persistence."),
    dict(id="PERS-STARTUP", name="New startup-folder item", severity="high", kind="file",
         field="path", re=r"(?i)start menu|startup", why="New executable/script in a per-user Startup folder."),
    dict(id="PERS-WMI-SUB", name="New WMI event subscription", severity="critical", kind="wmi",
         field="path", re=r".", why="WMI EventFilter/EventConsumer binding is file-less persistence."),

    # ---- eventlog ----
    dict(id="EVT-4688-SUSP", name="Security log: suspicious process creation", severity="high", kind="eventlog",
         field="cmdline", re=r"(?i)(-enc|certutil(\.exe)?\"?\s+.*urlcache|bitsadmin(\.exe)?\"?\s+.*/transfer)",
         why="Windows auditing (event 4688) independently observed the same launch pattern."),
    dict(id="EVT-4688-TEMP", name="Process launched from user-writable path", severity="high", kind="eventlog",
         field="path", re=r"(?i)\\appdata\\local\\temp\\|\\users\\public\\|\\windows\\temp\\|\\programdata\\",
         why="Kernel-fed Security audit (4688): executable launched from a directory any "
             "process can write to - the standard drop zone for staged implants."),
    dict(id="EVT-SAM-SAVE", name="Registry hive dump (4688)", severity="critical", kind="eventlog",
         field="cmdline", re=r"(?i)(reg(\.exe)?\"?\s+save\s+HKLM\\(SAM|SYSTEM|SECURITY)|secretsdump|ntdsutil.*\"ac i n t ds\")",
         why="Kernel-fed 4688: extracting SAM/SYSTEM/SECURITY hives - offline credential "
             "extraction prerequisite."),
    dict(id="EVT-LOG-CLEAR", name="Event log clearing (4688)", severity="critical", kind="eventlog",
         field="cmdline", re=r"(?i)(wevtutil(\.exe)?\"?\s+cl|clear-eventlog|Remove-WinEvent)",
         why="Kernel-fed 4688: clearing Windows event logs - anti-forensics."),
    dict(id="EVT-AUDIT-DISABLE", name="Security auditing disabled (4688)", severity="critical", kind="eventlog",
         field="cmdline", re=r"(?i)auditpol(\.exe)?\"?\s+/set\s+.*(/success:disable|/failure:disable|/clear)",
         why="Kernel-fed 4688: disabling audit policy to blind kernel-fed detection sources."),
    dict(id="EVT-7045", name="Service installed (event 7045)", severity="critical", kind="eventlog",
         field="eid", re=r"^7045$", why="System event log service-install record."),
    dict(id="EVT-4698", name="Scheduled task created (event 4698)", severity="high", kind="eventlog",
         field="eid", re=r"^4698$", why="Security event log scheduled-task creation record."),
    dict(id="EVT-4720", name="User account created (event 4720)", severity="high", kind="eventlog",
         field="eid", re=r"^4720$", why="New account creation during competition window."),

    # ---- network ----
    dict(id="NET-BEACON", name="Periodic beacon callback detected", severity="critical", kind="network",
         field="peer", re=r".", why="Beacon-cadence analysis: repeated outbound connections at a "
             "near-constant interval (+/- jitter) to one peer."),

    # ---- defensive-tamper ----
    dict(id="TAMPER-AUDIT", name="Security auditing disabled", severity="critical", kind="eventlog",
         field="eid", re=r"^1102$", why="Security audit log was cleared - classic anti-forensics move."),
    dict(id="TAMPER-DEFENDER", name="Defender exclusion added", severity="high", kind="process",
         field="cmdline", re=r"(?i)add-mppreference.*-exclusion",
         why="Attempt to add a Defender exclusion path - EDR/AV blinding attempt."),

    # ---- tranche 4: egress, lateral movement, dead-drop, firewall ----
    dict(id="PROC-EGRESS-TOOL", name="Tunneling/egress tool invocation", severity="critical", kind="process",
         field="cmdline", re=r"(?i)\b(ngrok|chisel|frpc|frps|ligolo|cloudflared|brook|rathole|revsocks|plink\.exe.*-R |ssh\.exe.*-R |socat.*EXEC)",
         why="Known reverse-tunnel / egress-bypass tooling - how red teams exfiltrate C2 out of "
             "a segmented CCDC network when direct egress is blocked."),
    dict(id="PROC-RMM-TOOL", name="Remote-management tool launch", severity="high", kind="process",
         field="cmdline", re=r"(?i)\b(teamviewer|anydesk|rustdesk|screenconnect|remotely|netsupport|vncserver|tightvnc)",
         why="Consumer remote-access tool launched during the competition window - a common "
             "interactive-access backdoor."),
    dict(id="PROC-PSEXESVC", name="PsExec service execution", severity="high", kind="process",
         field="cmdline", re=r"(?i)psexesvc(\.exe)?|psexec(\.exe)?\"?\s+\\\\|\-accepteula\s+\\\\",
         why="PsExec remote execution - the classic lateral-movement workhorse; on the target "
             "it should also raise the 7045 service-install event."),
    dict(id="PROC-WINRM-SESSION", name="WinRM lateral session host", severity="medium", kind="process",
         field="cmdline", re=r"(?i)wsmprovhost\.exe|winrm(\.exe)?\"?\s+(quickconfig|invoke|create)|invoke-command\s+-computername|new-pssession\s+-computername",
         why="WinRM remote-session activity - fileless lateral movement (CIM/PowerShell "
             "remoting) that never drops a service binary like PsExec does."),
    dict(id="PROC-NETSH-FIREWALL", name="Firewall rule modification", severity="high", kind="process",
         field="cmdline", re=r"(?i)netsh(\.exe)?\"?\s+.*?(advfirewall|firewall).*?\s+(add|delete|set)\b",
         why="Firewall rules changed - opening inbound holes for backdoor listeners or "
             "deleting containment rules."),
    dict(id="NET-DEADDROP", name="Dead-drop C2 channel usage", severity="high", kind="process",
         field="cmdline", re=r"(?i)(curl|wget|invoke-webrequest|invoke-restmethod|git(\.exe)?\"?\s+(clone|pull))\s+.*(raw\.githubusercontent|paste\.ee|pastebin|hastebin|ghostbin|transfer\.sh|anonfiles|file\.io|0x0\.st|dnslog|requestbin)",
         why="Command line pulling from a public paste/GitHub dead-drop service - the "
             "store-and-forward C2 channel that blends in with legitimate traffic."),

    # ---- 4688 twins of the tranche-4 rules: sub-second invocations the 3s
    # WMI poll can miss entirely are still seen by the kernel-fed audit log ----
    dict(id="EVT-EGRESS-TOOL", name="Tunneling/egress tool (4688)", severity="critical", kind="eventlog",
         field="cmdline", re=r"(?i)\b(ngrok|chisel|frpc|frps|ligolo|cloudflared|brook|rathole|revsocks|plink\.exe.*-R |ssh\.exe.*-R |socat.*EXEC)",
         why="Kernel-fed 4688: reverse-tunnel / egress-bypass tooling invoked."),
    dict(id="EVT-RMM-TOOL", name="Remote-management tool (4688)", severity="high", kind="eventlog",
         field="cmdline", re=r"(?i)\b(teamviewer|anydesk|rustdesk|screenconnect|remotely|netsupport|vncserver|tightvnc)",
         why="Kernel-fed 4688: consumer remote-access tool launched."),
    dict(id="EVT-PSEXESVC", name="PsExec execution (4688)", severity="high", kind="eventlog",
         field="cmdline", re=r"(?i)psexesvc(\.exe)?|psexec(\.exe)?\"?\s+\\\\|\-accepteula\s+\\\\",
         why="Kernel-fed 4688: PsExec remote execution."),
    dict(id="EVT-NETSH-FIREWALL", name="Firewall rule modification (4688)", severity="high", kind="eventlog",
         field="cmdline", re=r"(?i)netsh(\.exe)?\"?\s+.*?(advfirewall|firewall).*?\s+(add|delete|set)\b",
         why="Kernel-fed 4688: firewall rules changed."),
    dict(id="EVT-DEADDROP", name="Dead-drop fetch (4688)", severity="high", kind="eventlog",
         field="cmdline", re=r"(?i)(curl|wget|invoke-webrequest|invoke-restmethod|git(\.exe)?\"?\s+(clone|pull))\s+.*(raw\.githubusercontent|paste\.ee|pastebin|hastebin|ghostbin|transfer\.sh|anonfiles|file\.io|0x0\.st|dnslog|requestbin)",
         why="Kernel-fed 4688: pull from a public dead-drop service."),
]

_compiled = [(r, re.compile(r["re"])) for r in RULES]
for _r in RULES:
    state.rule_enabled[_r["id"]] = True

def evaluate(rec):
    """Run all rules for the record's kind against its fields; raise alerts on match.

    The persistence auditor and file scanner raise their own dedicated alerts,
    so their events are skipped here to avoid double-firing. Rules toggled off
    in the console are skipped.
    """
    if rec.get("source") in ("auditor", "filescan"):
        return []
    hits = []
    for rule, rx in _compiled:
        if rule["kind"] != rec.get("kind"):
            continue
        if not state.rule_enabled.get(rule["id"], True):
            continue
        val = rec.get("data", {}).get(rule["field"])
        if val is None:
            continue
        if rx.search(str(val)):
            a = state.raise_alert(rule["id"], rule["severity"], rule["name"],
                                  rule["why"], event=rec, data={"matched_field": rule["field"],
                                                                "matched_value": str(val)[:200]})
            hits.append(rule["id"])
    return hits

def test_sample(text):
    """Live-test panel backend: which rules would fire on this sample input?"""
    results = []
    for rule, rx in _compiled:
        if rule["re"] == ".":      # semantic catch-all rules - not text-matchable
            continue
        for kind, field in (("process", "cmdline"), ("eventlog", "cmdline"), ("eventlog", "path"),
                            ("eventlog", "eid"), ("network", "peer"), ("file", "path"),
                            ("file", "content_sig"), ("registry", "path"), ("task", "path"),
                            ("service", "path"), ("wmi", "path")):
            if rule["kind"] != kind:
                continue
            if rx.search(text):
                results.append({"rule": rule["id"], "name": rule["name"], "severity": rule["severity"],
                                "matched_field": field})
                break
    return results

def list_rules():
    return [{k: r[k] for k in ("id", "name", "severity", "kind", "why")} for r in RULES]
