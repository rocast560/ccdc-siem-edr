"""False-positive tuning: allowlists, self-exclusion, and alert cooldowns.

Observed FP sources in this deployment and their fixes:
- the EDR's own sensor subprocesses (wevtutil/powershell/netstat spawned every
  few seconds) tripping command-line rules   -> SELF_PATTERNS exclusion
- dev-tooling listeners (bun, winget shims) on high ports               -> listener
  scope (non-loopback binds only) + LISTENER_ALLOW paths
- the same entity re-alerting every cycle (pipes, listeners, modules)    ->
  raise_alert cooldown: repeats increment the original alert's count
- Microsoft-managed DLLs appearing in many processes (HOOK-DLL)          ->
  correlation only counts modules in genuinely attacker-writable paths
"""
import os, re, time, threading

# ---- self-exclusion: our own sensor tooling command lines ---------------
SELF_PATTERNS = re.compile(
    r"(?i)(Get-CimInstance\s+Win32_|wevtutil\s+qe|ConvertTo-Json\s+-Compress"
    r"|logman\s+(start|stop|query)|tracerpt|tasklist\s+/fo|netstat\s+-ano"
    r"|schtasks\s+/query|Get-ScheduledTask|Resolve-DnsName\s+-ErrorAction"
    r"|Get-NetTCPConnection|auditpol\s+/get|CCDC-EDR-SIEM-design[\\\\/]edr[\\\\/]state)"
)

def is_sensor_noise(cmdline):
    return bool(SELF_PATTERNS.search(cmdline or ""))

# ---- listener scope -------------------------------------------------------
LISTENER_ALLOW_PREFIXES = (
    "c:\\users\\administrator\\.bun\\", "c:\\program files\\windowsapps\\",
    "c:\\users\\administrator\\appdata\\local\\microsoft\\winget\\",
)
LISTENER_ALLOW_NAMES = {"bun.exe", "psmux.exe", "zcode.exe", "code.exe", "cursor.exe"}

def listener_is_fp(path, name, bind_addr):
    if bind_addr and ("127.0.0.1" in bind_addr or "[::1]" in bind_addr):
        return True                       # loopback-only dev servers: not exposed
    pl = (path or "").lower()
    nl = (name or "").lower()
    if nl in LISTENER_ALLOW_NAMES:
        return True
    return any(pl.startswith(p) for p in LISTENER_ALLOW_PREFIXES)

# ---- hook-DLL correlation scope -------------------------------------------
HOOKDLL_SUSPICIOUS_PREFIXES = (
    "c:\\windows\\temp\\", "c:\\users\\public\\", "c:\\programdata\\",
    "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
)
def hookdll_is_suspicious(module_path):
    pl = (module_path or "").lower()
    if "\\appdata\\local\\microsoft\\" in pl or "\\windowsapps\\" in pl:
        return False
    return any(p in pl for p in HOOKDLL_SUSPICIOUS_PREFIXES)

# ---- alert cooldown --------------------------------------------------------
COOLDOWN_S = 600          # 10 minutes per (rule, entity)
_lock = threading.Lock()
_recent = {}              # (rule, key) -> alert dict

def cooldown_key(rule_id, data):
    d = data or {}
    # entity-specific identifiers first; a bare path is shared by every child
    # of the same interpreter, so it only counts when combined with the pid
    for k in ("pipe", "peer", "service", "assembly", "port"):
        if d.get(k) is not None:
            return (rule_id, "%s:%s" % (k, d[k]))
    if d.get("pid") is not None:
        return (rule_id, "pid:%s:%s" % (d["pid"], d.get("path", "")))
    return (rule_id, str(sorted(d.items()))[:80])

def repeat_or_none(rule_id, data):
    """Return the existing alert if this (rule, entity) fired recently."""
    with _lock:
        hit = _recent.get(cooldown_key(rule_id, data))
        if hit and time.time() - hit.get("ts", 0) < COOLDOWN_S:
            hit["repeat"] = hit.get("repeat", 1) + 1
            return hit
    return None

def remember(rule_id, data, alert):
    with _lock:
        _recent[cooldown_key(rule_id, data)] = alert
        # prune
        now = time.time()
        for k in [k for k, v in _recent.items() if now - v.get("ts", 0) > COOLDOWN_S * 2]:
            del _recent[k]
