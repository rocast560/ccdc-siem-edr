"""Rules engine: Sigma-like JSON rules evaluated against normalized events.

Rule shape:
{
  "id": "PROC-ENC-PS",
  "name": "Encoded PowerShell command line",
  "severity": "high",
  "source": "process",                 # which sensor's events it applies to
  "kind": "process",
  "selection": {"field": "cmdline", "re": "-enc(odedcommand)?\\s"},
  "why": "Base64-encoded PowerShell is a common stager launch pattern ..."
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
         field="cmdline", re=r"(?i)rundll32(\.exe)?\s*$",
         why="Argument-less rundll32 is the classic Cobalt Strike spawn posture: the beacon "
             "injects into the suspended process, so no DLL argument ever appears."),
    dict(id="PROC-LOLBIN-DOWNLOAD", name="LOLBIN network fetch", severity="high", kind="process",
         field="cmdline", re=r"(?i)(certutil\s+-urlcache|bitsadmin\s+/transfer|mshta\s+http|regsvr32\s+/i:http)",
         why="Signed LOLBIN used to fetch remote payload - common C2 stager delivery."),
    dict(id="PROC-SUSP-PARENT", name="Office/spoolsv spawning script interpreter", severity="critical", kind="process",
         field="cmdline", re=r"(?i)^(winword|excel|spoolsv|explorer)\.exe\s+(\S+\s+)*(powershell|cmd|wscript|cscript|rundll32)",
         why="Unexpected parent-child pair: document/spooler process launching an interpreter "
             "is the signature of macro execution or a spooler-context implant."),
    dict(id="PROG-IMPLANT-LAUNCH", name="Signature hit on launched process image", severity="critical", kind="process",
         field="sig", re=r".", why="Process launched from an image whose bytes matched an implant signature rule."),
    dict(id="PROC-MIMIKATZ-CLI", name="Credential-dump tooling command line", severity="critical", kind="process",
         field="cmdline", re=r"(?i)(sekurlsa::logonpasswords|lsadump::sam|procdump.*-ma.*lsass|comsvcs\.dll,MiniDump)",
         why="Command line matches credential-dumping invocation patterns (mimikatz modules, "
             "LSASS minidump via comsvcs or procdump)."),

    # ---- files ----
    dict(id="FILE-IMPLANT-SIG", name="Implant signature match on file", severity="critical", kind="file",
         field="path", re=r".", why="Static byte-signature pack matched this file on write/scan."),
    dict(id="FILE-WEBROOT-SHELL", name="Webshell-pattern file written", severity="critical", kind="file",
         field="content_sig", re=r"webshell", why="File content matched webshell function patterns."),
    dict(id="FILE-TOME", name="Eldritch tome / C2 script dropped", severity="high", kind="file",
         field="content_sig", re=r"eldritch", why="File content matched Realm imix 'eldritch' tome indicators."),

    # ---- registry / persistence (auditor diffs surface these) ----
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
         field="cmdline", re=r"(?i)(-enc|certutil.*urlcache|bitsadmin.*/transfer)",
         why="Windows auditing (event 4688) independently observed the same launch pattern."),
    dict(id="EVT-4688-TEMP", name="Process launched from user-writable path", severity="high", kind="eventlog",
         field="path", re=r"(?i)\\appdata\\local\\temp\\|\\users\\public\\|\\windows\\temp\\|\\programdata\\",
         why="Kernel-fed Security audit (4688): executable launched from a directory any "
             "process can write to - the standard drop zone for staged implants."),
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
    """Live-test panel backend: which rules would fire on this sample input?

    The sample is treated as a command line (process rules) and as a fake
    event per kind so every applicable rule gets a chance to match.
    """
    results = []
    for rule, rx in _compiled:
        if rule["re"] == ".":      # semantic catch-all rules (auditor/network fed) - not text-matchable
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
