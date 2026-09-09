"""Implant confidence engine — fuse atomic alerts into one scored verdict.

This is the "verdict layer" commercial EDRs put on top of telemetry: instead of
N independent alerts, every signal is attached to an ENTITY (the binary, the
pid, the C2 peer) and weighted. The summed evidence becomes a 0-99 confidence
score:

    >= 85  CONFIRMED implant   (the Implants screen's "99% sure" tier)
    >= 60  LIKELY implant
    >= 35  suspicious          (watch, don't act)
    <  35  ignored

Deliberately transparent: every contributing rule, its weight and the alert it
came from ship with the verdict, so an analyst can audit why the machine is
confident. Entity status lifecycle (active -> suspended/quarantined/killed ->
verified-inactive) is tracked in state.implant_status and verified against
live process liveness, firewall rules and beacon silence.
"""
import ctypes, os, re, sys, threading, time

from . import state

# rule -> (weight, category). Weights calibrated so a single weak signal never
# passes "suspicious" but two strong ones reach "confirmed".
WEIGHTS = {
    # -- C2 callbacks (the core implant signal) --
    "NET-BEACON": (45, "c2-cadence"),
    "DNS-BEACON": (40, "c2-cadence"),
    "ICMP-BEACON": (38, "c2-cadence"),
    "NET-DEADDROP": (20, "c2-cadence"),
    "PKT-SOCKET": (14, "c2-evasion"),
    # -- memory-only execution / injection --
    "MEM-HOLLOWED": (45, "memory"),
    "MEM-RWX-UNBACKED": (28, "memory"),
    "MEM-PROMOTE": (30, "memory"),
    "MEM-RWX-NEW": (16, "memory"),
    "SYSCALL-STUB": (22, "memory"),
    "PROC-XHANDLE": (32, "injection"),
    "THREAD-HIJACK": (30, "injection"),
    "THREAD-UNBACKED": (24, "injection"),
    "STACK-UNBACKED": (22, "injection"),
    "NTDLL-TAMPER": (30, "injection"),
    "HOOK-DLL": (16, "injection"),
    "MOD-SIDELOAD": (18, "injection"),
    # -- static identification --
    "FILE-IMPLANT-SIG": (50, "signature"),
    "FILE-TOME": (30, "signature"),
    "FILE-WEBROOT-SHELL": (35, "signature"),
    "TIME-STOMP": (15, "anti-forensics"),
    "PROG-IMPLANT-LAUNCH": (35, "execution"),
    # -- credential access / tradecraft --
    "LSASS-HANDLE": (28, "credential"),
    "PROC-MIMIKATZ-CLI": (30, "credential"),
    "PROC-NOPS-AMSI": (20, "evasion"),
    "PROC-MASQ": (18, "evasion"),
    "SPAWN-SHELL": (15, "execution"),
    "NET-PIPE": (12, "c2-evasion"),
    # -- behavioral / process lineage --
    "PROC-SUSP-PARENT": (14, "lineage"),
    "EVT-SUSP-PARENT": (14, "lineage"),
    "PROC-SCRIPTHOST": (10, "lineage"),
    "EVT-SCRIPTHOST": (10, "lineage"),
    "PROC-RUNDLL-NOARG": (12, "lineage"),
    "PROC-ENC-PS": (12, "evasion"),
    "EVT-4688-SUSP": (12, "lineage"),
    "EVT-4688-TEMP": (10, "lineage"),
    # -- tamper --
    "TAMPER-DEFENDER": (30, "tamper"),
    "TAMPER-AUDIT": (18, "tamper"),
    "PROC-AUDIT-DISABLE": (18, "tamper"),
    "EVT-AUDIT-DISABLE": (18, "tamper"),
    "EVT-LOG-CLEAR": (15, "tamper"),
    "PROC-LOG-CLEAR": (15, "tamper"),
    "SENSOR-WATCHDOG": (0, "tamper"),
    # -- persistence (weaker alone: admin tooling shares these) --
    "PERS-RUNKEY": (15, "persistence"),
    "PERS-SERVICE": (18, "persistence"),
    "PERS-STARTUP": (15, "persistence"),
    "PERS-TASK": (15, "persistence"),
    "PERS-WMI-SUB": (22, "persistence"),
    "EVT-7045": (18, "persistence"),
    "EVT-4698": (22, "persistence"),
    # -- response actions themselves are never evidence --
    "RESP-KILL": (0, "response"), "RESP-SUSPEND": (0, "response"),
    "RESP-QUAR": (0, "response"), "RESP-BLOCK": (0, "response"),
    "RESP-QUARANTINE": (0, "response"), "RESP-ISOLATE": (0, "response"),
}

TIER_CONFIRMED = 85
TIER_LIKELY = 60
TIER_SUSPICIOUS = 35

# Verdict-layer allowlist (blue-team infrastructure the sensors should never
# crown "implant"): the system interpreter that runs the EDR itself, and this
# host's agent console. Path-keyed so a renamed lookalike is still scored.
IMG_ALLOWLIST = (
    os.path.dirname(os.path.abspath(sys.executable)).lower() + os.sep,
    r"c:\program files\python313" + os.sep,
    r"c:\users\administrator\appdata\local\programs\zcode" + os.sep,
)

def _w(rule):
    if rule in WEIGHTS:
        return WEIGHTS[rule]
    for pre in ("PERS-", "EVT-", "PROC-", "MEM-"):
        if rule.startswith(pre):
            return (15, "behavioral")
    return (8, "other")

def tier_of(score):
    if score >= TIER_CONFIRMED: return "confirmed"
    if score >= TIER_LIKELY: return "likely"
    if score >= TIER_SUSPICIOUS: return "suspicious"
    return "noise"

# ---------------------------------------------------------------- liveness

def pid_alive(pid):
    """True if the pid still exists (OpenProcess + STILL_ACTIVE probe)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k32.OpenProcess(0x1000, False, pid)      # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            code = ctypes.c_ulong(0)
            k32.GetExitCodeProcess(h, ctypes.byref(code))
            return code.value == 259                  # STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    except Exception:
        return False

# ---------------------------------------------------------------- entity build

def _alert_fields(a):
    """(pid, path, name, peer) out of an alert's data, tolerating sensor variance."""
    d = a.get("data") or {}
    pid = d.get("pid") or d.get("ProcessId") or d.get("target_pid")
    path = (d.get("path") or d.get("image") or d.get("exe") or
            d.get("ExecutablePath") or d.get("file") or "").lower() or None
    name = d.get("name") or d.get("process") or d.get("Name")
    peer = d.get("peer") or d.get("remote") or d.get("ip")
    ev = a.get("event") or {}
    if not pid: pid = ev.get("pid")
    if not path: path = (ev.get("path") or ev.get("image") or "").lower() or None
    if not name: name = ev.get("name")
    if not peer: peer = ev.get("peer")
    return pid, path, name, peer

def _entity_key(path, pid, peer):
    if path:
        return "path:" + path
    if pid:
        return "pid:" + str(pid)
    if peer:
        return "peer:" + str(peer)
    return None

def compute():
    """Build the scored implant list from the alert ring. Called by /api/implants."""
    with state.LOCK:
        alerts = [dict(a) for a in state.alerts]
    ent = {}

    def bucket(key):
        if key not in ent:
            ent[key] = {"key": key, "path": None, "name": None, "pids": [],
                        "peers": [], "rules": {}, "first": time.time(), "last": 0}
        return ent[key]

    for a in alerts:
        rule = a.get("rule") or ""
        if rule.startswith("RESP-"):
            continue
        w, cat = _w(rule)
        if w <= 0:
            continue
        pid, path, name, peer = _alert_fields(a)
        key = _entity_key(path, pid, peer)
        if not key:
            continue
        b = bucket(key)
        if path and not b["path"]: b["path"] = path
        if name and not b["name"]: b["name"] = name
        if pid and int(pid) not in b["pids"]: b["pids"].append(int(pid))
        if peer and str(peer) not in b["peers"]: b["peers"].append(str(peer))
        b["first"] = min(b["first"], a.get("ts") or time.time())
        b["last"] = max(b["last"], a.get("ts") or 0)
        e = b["rules"].get(rule)
        if e:
            e["count"] += 1
            e["ts"] = max(e["ts"], a.get("ts") or 0)
        else:
            b["rules"][rule] = {"w": w, "cat": cat, "ts": a.get("ts") or 0,
                                "title": a.get("title") or "", "count": 1}

    # merge pid-only entities into path entities when the pid was seen there
    paths = [k for k in ent if k.startswith("path:")]
    for k in list(ent):
        if not k.startswith("pid:"):
            continue
        me = ent[k]
        for pk in paths:
            if me is ent[pk]:
                continue
            if set(me["pids"]) & set(ent[pk]["pids"]):
                tgt = ent[pk]
                tgt["pids"] = list(set(tgt["pids"]) | set(me["pids"]))
                tgt["peers"] = list(set(tgt["peers"]) | set(me["peers"]))
                tgt["first"] = min(tgt["first"], me["first"])
                tgt["last"] = max(tgt["last"], me["last"])
                for r, e in me["rules"].items():
                    if r not in tgt["rules"]:
                        tgt["rules"][r] = e
                del ent[k]
                break

    out = []
    for key, b in ent.items():
        score = 0
        evidence = []
        for r, e in sorted(b["rules"].items(), key=lambda kv: -kv[1]["w"]):
            # repeat hits of the same rule add diminishing weight (max +8)
            score += min(8, (e["count"] - 1) * 2)
            score += e["w"]
            evidence.append({"rule": r, "weight": e["w"], "count": e["count"],
                             "ts": e["ts"], "title": e["title"], "category": e["cat"]})
        score = min(99, score)
        if score < TIER_SUSPICIOUS:
            continue
        # blue-team infrastructure: sensors may still alert, but the verdict
        # layer refuses to crown trusted images as implants
        if b["path"] and any(b["path"].startswith(p) for p in IMG_ALLOWLIST):
            state.norm_event("correlation", "audit", "info",
                             "Implant verdict suppressed (trusted image): " +
                             os.path.basename(b["path"]),
                             {"path": b["path"], "raw_score": score,
                              "signals": sorted(b["rules"])[:6]})
            continue
        b.update({"score": score, "tier": tier_of(score), "evidence": evidence,
                  "name": b["name"] or (os.path.basename(b["path"]) if b["path"] else key)})
        out.append(b)

    out.sort(key=lambda x: -x["score"])

    # status lifecycle from recorded actions + live liveness
    with state.LOCK:
        statuses = dict(state.implant_status)
        protect = bool(state.protect_mode)
    for b in out:
        st = statuses.get(b["key"])
        if st:
            b["status"] = st["status"]
            b["status_since"] = st["ts"]
            b["status_by"] = st.get("by", "analyst")
        else:
            b["status"] = "active"
            b["status_since"] = b["first"]
            b["status_by"] = "sensor"
        if b["status"] in ("active", "monitoring"):
            b["alive"] = any(pid_alive(p) for p in b["pids"]) if b["pids"] else None
        else:
            b["alive"] = any(pid_alive(p) for p in b["pids"]) if b["pids"] else False
        # re-infection: a contained path must show POSITIVE evidence of coming
        # back — a live pid alone is not enough (termination lag keeps exit
        # code 259 briefly, and Windows recycles pids). Require fresh alerts
        # for this entity after the containment action, plus a grace window.
        if b["status"] in ("quarantined", "killed", "quarantined-verified",
                           "killed-verified") and b["alive"]:
            acted_at = st.get("ts") or 0
            fresh_evidence = b["last"] > acted_at + 5
            past_grace = time.time() - acted_at > 30
            if fresh_evidence and past_grace:
                b["status"] = "active"
                b["status_by"] = "sensor"
                b["reinfection"] = True
                state.implant_status[b["key"]] = {"status": "active", "ts": time.time(),
                                                  "by": "sensor",
                                                  "detail": "re-infection: contained path is alive again"}
                state.save_implant_status()
    return {"protect_mode": protect, "thresholds": {"confirmed": TIER_CONFIRMED,
                                                    "likely": TIER_LIKELY,
                                                    "suspicious": TIER_SUSPICIOUS},
            "implants": out}

def lookup(key):
    """One scored entity by key (for verify endpoints)."""
    for b in compute()["implants"]:
        if b["key"] == key:
            return b
    return None

# ---------------------------------------------------------------- verification

def _fw_rule_exists(peer):
    r = _run(["netsh", "advfirewall", "firewall", "show", "rule",
              "name=CCDC-EDR-Block-" + str(peer)])
    return bool(r) and "No rules match" not in r

def _run(cmd):
    try:
        import subprocess
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return ""

def _peer_last_activity(peer, own_pids=None):
    """Last observed flow/callback time for a peer. When own_pids is given,
    only flows FROM those processes count (containment silence = the contained
    process stopped calling back — other processes sharing the IP, e.g. all
    loopback console traffic, are separate entities)."""
    from . import network
    last = 0
    own = {int(p) for p in (own_pids or [])}
    for (pid, p), ts in getattr(network, "_flows", {}).items():
        if own and pid not in own:
            continue
        if str(p) == str(peer) and ts:
            last = max(last, ts[-1])
    return last

def verify_containment(key):
    """Re-check that a containment action actually holds. Returns check list."""
    b = lookup(key) or {"key": key, "pids": [], "peers": [], "path": None}
    checks = []
    # 1. processes gone
    if b["pids"]:
        alive = [p for p in b["pids"] if pid_alive(p)]
        checks.append({"name": "process terminated", "pass": not alive,
                       "detail": ("no known pids alive" if not alive
                                  else "still alive: " + ", ".join(map(str, alive)))})
    else:
        checks.append({"name": "process terminated", "pass": True,
                       "detail": "no pid recorded for this entity"})
    # 2. binary removed from origin
    if b["path"]:
        gone = not os.path.isfile(b["path"])
        checks.append({"name": "binary vaulted", "pass": gone,
                       "detail": ("no longer at " + b["path"]) if gone
                                 else "still present at origin path"})
    # 3. egress to C2 peers firewalled
    if b["peers"]:
        missing = [p for p in b["peers"] if not _fw_rule_exists(p)]
        checks.append({"name": "C2 egress blocked", "pass": not missing,
                       "detail": (", ".join(b["peers"]) + " firewalled") if not missing
                                 else "no firewall rule for " + ", ".join(missing)})
    # 4. beacon silence since the action (the contained process itself)
    st = state.implant_status.get(key) or {}
    since = st.get("ts") or 0
    if b["peers"] and since:
        act = max(_peer_last_activity(p, b.get("pids")) for p in b["peers"])
        quiet = act <= since + 2
        checks.append({"name": "C2 silent since action", "pass": quiet,
                       "detail": ("no callbacks from contained pids since the action"
                                  if quiet else "contained pid STILL calling back")})
    all_pass = all(c["pass"] for c in checks) if checks else False
    # a quarantined entity that passes every check earns the verified state
    if all_pass and st.get("status") in ("quarantined", "killed"):
        state.implant_status[key] = dict(st, status=st["status"] + "-verified",
                                         verified_ts=time.time())
        state.save_implant_status()
    return {"key": key, "all_pass": all_pass, "checks": checks,
            "status": state.implant_status.get(key, {}).get("status", "unknown")}

# ---------------------------------------------------------------- protect mode

def maybe_auto_quarantine():
    """Detect-vs-Protect policy: auto-contain entities that cross the confirmed
    threshold. Runs in its own thread (raises alerts + taskkill are slow)."""
    if not state.protect_mode:
        return
    try:
        snap = compute()
    except Exception:
        return
    for b in snap["implants"]:
        if b["tier"] != "confirmed" or b["status"] not in ("active", "monitoring"):
            continue
        threading.Thread(target=_auto_contain, args=(b,), daemon=True).start()

def _auto_contain(b):
    from . import responder
    state.implant_status[b["key"]] = {"status": "quarantined", "ts": time.time(),
                                      "by": "protect-mode", "detail": b["name"]}
    ok, msg = responder.quarantine_entity(b["pids"][0] if b["pids"] else 0,
                                          peers=b["peers"], path=b["path"],
                                          by="protect-mode")
    if not ok:
        state.implant_status[b["key"]] = {"status": "active", "ts": time.time(),
                                          "by": "sensor", "detail": "auto-contain failed: " + str(msg)}
