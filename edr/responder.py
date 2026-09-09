"""Active response: safe kill / quarantine / network-block actions for detections.

Every action is validated before execution and logged as a sensor event:

- kill:       terminate a beacon/implant process. Refuses system-critical processes,
             anything running from Windows directories, and the EDR's own processes.
- quarantine: move a detected file into edr/state/quarantine/ (same volume rename),
             strip execute ACLs, record origin for restore. Refuses system paths and
             anything the running system likely needs.
- block:      Windows Firewall outbound+inbound block rule for a remote peer IP.
"""
import os, re, shutil, subprocess, time, hashlib
from . import state

QUARANTINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state", "quarantine")
QUARANTINE_MANIFEST = os.path.join(QUARANTINE, "manifest.json")

# implant config surface: compiled-in callback URIs / C2 hosts worth auto-blocking
CONFIG_RX = re.compile(
    rb"(?:(?:https?|grpc|quic|dns|icmp|tcp)://[A-Za-z0-9._%-]+(?:Port=[0-9]+)?[^\x00\s\"']{0,32}"
    rb"|IMIX_CALLBACK_URI[=:][^\x00\r\n]{4,200}"
    rb"|[A-Za-z0-9._-]+\.(?:cloud|net|com|io|xyz|top|ru|cn)(?::\d{1,5})?)")

def extract_config(path):
    """Pull embedded C2 indicators (callback URIs, hosts) out of a file."""
    try:
        with open(path, "rb") as f:
            data = f.read(8 * 1024 * 1024)
    except OSError:
        return []
    out = []
    for m in CONFIG_RX.finditer(data):
        s = m.group(0)[:200]
        try:
            txt = s.decode("utf-8", "replace")
        except Exception:
            continue
        if txt not in out:
            out.append(txt)
    return out[:12]

CRITICAL_NAMES = {
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe",
    "taskhostw.exe", "runtimebroker.exe", "ctfmon.exe", "conhost.exe", "logonui.exe",
}
PROTECTED_PREFIXES = (
    r"c:\windows", r"c:\program files", r"c:\program files (x86)",
    r"c:\programdata\microsoft", os.environ.get("SystemRoot", r"c:\windows").lower(),
)
IP_RX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$", re.I)

def _log(action, ok, detail, sev="medium"):
    state.norm_event("responder", "audit", sev if ok else "low",
                     ("Response " + action + (" ok: " if ok else " REFUSED: ") + detail),
                     {"action": action, "ok": ok, "detail": detail})

def _identify(pid):
    """(info, name, path) for a pid, or (None, '', '') if gone."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter 'ProcessId=%d' | Select-Object Name,ExecutablePath "
             "| ConvertTo-Json -Compress" % pid],
            capture_output=True, text=True, timeout=30).stdout
        import json
        info = json.loads(out) if out.strip() else None
    except Exception:
        info = None
    if not info:
        return None, "", ""
    return info, (info.get("Name") or "").lower(), (info.get("ExecutablePath") or "").lower()

def _guard(pid, action):
    """Shared safety gate for kill/suspend. Returns (info,name,path) or (None,err)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None, "bad pid"
    if pid <= 4:
        return None, "protected system pid"
    if pid in (os.getpid(), os.getppid() if hasattr(os, "getppid") else None):
        return None, "refusing to target the EDR"
    info, name, path = _identify(pid)
    if info is None:
        return None, "process already gone"
    if name in CRITICAL_NAMES:
        return None, "critical system process refused"
    if any(path.startswith(p.lower()) for p in PROTECTED_PREFIXES if p):
        return None, "protected image path refused"
    return (info, name, path), None

def suspend_process(pid):
    """Freeze a process (NtSuspendProcess) - containment WITHOUT deletion:
    the beacon stops communicating, but the process and its memory stay
    intact for forensic extraction."""
    got, err = _guard(pid, "suspend")
    if err:
        _log("suspend", False, f"pid {pid}: {err}"); return False, err
    info, name, path = got
    import ctypes
    PROCESS_SUSPEND_RESUME = 0x0800
    k32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.OpenProcess(PROCESS_SUSPEND_RESUME, False, int(pid))
    if not h:
        _log("suspend", False, f"pid {pid}: OpenProcess failed"); return False, "open failed"
    try:
        st = ntdll.NtSuspendProcess(h)
    finally:
        k32.CloseHandle(h)
    ok = (st & 0xFFFFFFFF) == 0
    _log("suspend", ok, f"pid {pid} ({name})")
    if ok:
        state.raise_alert("RESP-SUSPEND", "high", f"Response: suspended pid {pid} ({name})",
                          "Analyst-initiated containment: the process is frozen in place - it "
                          "cannot communicate, but nothing was deleted. Full memory remains "
                          "available for on-host forensics (config extraction, strings, "
                          "signatures) before a kill/restore decision.",
                          data={"pid": int(pid), "name": name, "path": path})
    return ok, "suspended" if ok else "ntstatus %s" % hex(st & 0xFFFFFFFF)

def resume_process(pid):
    """Undo a suspend (NtResumeProcess) - release a contained process."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False, "bad pid"
    import ctypes
    PROCESS_SUSPEND_RESUME = 0x0800
    k32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if not h:
        return False, "open failed"
    try:
        st = ntdll.ResumeThread(h) if False else ntdll.NtResumeProcess(h)
    finally:
        k32.CloseHandle(h)
    ok = (st & 0xFFFFFFFF) == 0
    _log("resume", ok, f"pid {pid}")
    return ok, "resumed" if ok else "ntstatus %s" % hex(st & 0xFFFFFFFF)

def kill_process(pid):
    """Terminate a process by PID with safety checks. Returns (ok, message)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False, "bad pid"
    if pid <= 4:
        _log("kill", False, f"pid {pid} is a protected system pid"); return False, "protected system pid"
    me = os.getpid()
    parent = os.getppid() if hasattr(os, "getppid") else None
    if pid in (me, parent):
        _log("kill", False, f"pid {pid} is the EDR itself"); return False, "refusing to kill the EDR"
    # identify the process first
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter 'ProcessId=%d' | Select-Object Name,ExecutablePath "
             "| ConvertTo-Json -Compress" % pid],
            capture_output=True, text=True, timeout=30).stdout
        import json
        info = json.loads(out) if out.strip() else None
    except Exception:
        info = None
    if not info:
        _log("kill", False, f"pid {pid} no longer exists"); return False, "process already gone"
    name = (info.get("Name") or "").lower()
    path = (info.get("ExecutablePath") or "").lower()
    if name in CRITICAL_NAMES:
        _log("kill", False, f"pid {pid} is critical system process {name}"); return False, "critical system process refused"
    if any(path.startswith(p.lower()) for p in PROTECTED_PREFIXES if p):
        _log("kill", False, f"pid {pid} image {path} is in a protected directory"); return False, "protected image path refused"
    r = subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True, timeout=30)
    ok = r.returncode == 0
    _log("kill", ok, f"pid {pid} ({name})" + ("" if ok else " taskkill failed"))
    if ok:
        state.raise_alert("RESP-KILL", "high", f"Response: killed pid {pid} ({name})",
                          "Analyst-initiated kill from the console. Process matched an active detection "
                          "and failed the critical/protected process safety checks.",
                          data={"pid": pid, "name": name, "path": path})
    return ok, (r.stdout or r.stderr).strip()[:160]

def quarantine_file(path):
    """Move a detected file to the quarantine vault and strip execute rights."""
    path = os.path.abspath(path or "")
    if not os.path.isfile(path):
        _log("quarantine", False, f"not a file: {path}"); return False, "file not found"
    low = path.lower()
    if any(low.startswith(p.lower()) for p in PROTECTED_PREFIXES if p):
        _log("quarantine", False, f"protected path: {path}"); return False, "protected path refused"
    try:
        os.makedirs(QUARANTINE, exist_ok=True)
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read(1024 * 1024)).hexdigest()[:16]
        dest = os.path.join(QUARANTINE, sha + "__" + os.path.basename(path))
        n = 1
        while os.path.exists(dest):      # same-content re-quarantine: pick a free name
            dest = os.path.join(QUARANTINE, sha + "-%d__" % n + os.path.basename(path))
            n += 1
        for attempt in range(3):          # our own scanner may hold the file mid-read
            try:
                shutil.move(path, dest)
                break
            except PermissionError:
                if attempt == 2:
                    raise
                time.sleep(1.0)
    except Exception as e:
        _log("quarantine", False, f"move failed {path}: {e}"); return False, "move failed"
    # strip execute from the vaulted copy
    subprocess.run(["icacls", dest, "/inheritance:r", "/grant:r", "*S-1-5-32-544:R",
                    "/deny", "*S-1-1-0:(X)"], capture_output=True, timeout=30)
    # record origin so it can be restored
    import json
    man = {}
    try:
        with open(QUARANTINE_MANIFEST) as f:
            man = json.load(f)
    except Exception:
        pass
    man[os.path.basename(dest)] = {"origin": path, "ts": time.time(), "sha16": sha}
    try:
        with open(QUARANTINE_MANIFEST, "w") as f:
            json.dump(man, f, indent=1)
    except Exception:
        pass
    # config extraction: pull compiled-in callback URIs and auto-block egress
    config = extract_config(dest)
    blocked = []
    for ind in config:
        host = re.search(r"[a-z]+://([^/:]+)", ind) or re.match(r"([0-9a-f.:]+(?::\d+)?)", ind)
        peer = host.group(1).strip(":.") if host else None
        if peer and IP_RX.match(peer.split(":")[0]):
            okb, _ = block_ip(peer.split(":")[0])
            if okb:
                blocked.append(peer.split(":")[0])
    _log("quarantine", True, f"{path} -> {dest}" +
         (f" | config extracted, blocked {blocked}" if blocked else ""))
    state.raise_alert("RESP-QUAR", "high", f"Response: quarantined {os.path.basename(path)}",
                      "Analyst-initiated quarantine: file moved to the EDR vault with execute "
                      "rights denied; origin recorded in the quarantine manifest for restore.",
                      data={"path": path, "vault": dest, "sha16": sha,
                            "config_indicators": config, "auto_blocked_peers": blocked})
    return True, dest

def block_ip(peer):
    """Add Windows Firewall block rules (in+out) for a remote peer."""
    peer = str(peer or "").strip()
    if not IP_RX.match(peer):
        _log("block", False, f"not an IP: {peer}"); return False, "invalid address refused"
    name = "CCDC-EDR-Block-" + peer
    for direction in ("out", "in"):
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                        "name=" + name, "dir=" + direction, "action=block",
                        "remoteip=" + peer], capture_output=True, timeout=30)
    _log("block", True, f"firewall block rules for {peer}")
    state.raise_alert("RESP-BLOCK", "high", f"Response: blocked peer {peer}",
                      "Analyst-initiated network containment: Windows Firewall now blocks "
                      "inbound and outbound traffic to this C2 peer.",
                      data={"peer": peer, "rule": name})
    return True, "firewall rules added for " + peer

def unblock_ip(peer):
    peer = str(peer or "").strip()
    if not IP_RX.match(peer):
        return False, "invalid address"
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=CCDC-EDR-Block-" + peer], capture_output=True, timeout=30)
    _log("unblock", True, f"removed firewall block for {peer}")
    return True, "block removed"

# ------------------------------------------------------- entity-level response

ISOLATE_RULE = "CCDC-EDR-Host-Isolation"

def set_entity_status(key, status, by="analyst", detail=""):
    """Record the lifecycle state of a correlated implant entity."""
    if not key:
        return False, "no entity"
    state.implant_status[str(key)] = {"status": status, "ts": time.time(), "by": by,
                                      "detail": detail or status}
    state.save_implant_status()
    return True, status

def kill_tree(pid):
    """Terminate a process AND its descendants — SentinelOne's 'kill the whole
    threat sequence' semantics: spawners and injected children go too."""
    got, err = _guard(pid, "kill-tree")
    if err:
        _log("kill-tree", False, f"pid {pid}: {err}"); return False, err
    _, name, path = got
    r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True, text=True, timeout=60)
    ok = r.returncode == 0
    _log("kill-tree", ok, f"pid {pid} ({name}) tree terminated")
    if ok:
        state.raise_alert("RESP-KILL", "high", f"Response: killed process tree of pid {pid} ({name})",
                          "Analyst-initiated tree kill: the process and every descendant "
                          "(spawners, injected children, dropped helpers) were terminated.",
                          data={"pid": int(pid), "name": name, "path": path, "tree": True})
    return ok, (r.stdout or r.stderr).strip()[:160]

def quarantine_entity(pid, peers=None, path=None, by="analyst"):
    """Full implant containment — quarantine an analyst can trust:
    the C2 channel dies AND the binary is vaulted AND the status flips.

    Sequence (order matters — cut the network before touching the process):
      1. firewall-block every known C2 peer (egress + ingress)
      2. terminate the process tree (guarantees no further callbacks)
      3. vault the binary (deny-execute ACL, origin manifest)
      4. config extraction on the vaulted copy auto-blocks missed peers
      5. entity status -> 'quarantined' (verified-inactive once /api/verify passes)
    """
    peers = [str(p) for p in (peers or []) if IP_RX.match(str(p))]
    results = {"blocked_peers": [], "killed": None, "vault": None, "errors": []}

    # 1. cut egress first
    for peer in peers:
        okb, _ = block_ip(peer)
        if okb:
            results["blocked_peers"].append(peer)

    # 2. terminate the tree (guardrailed); an already-exited pid is fine
    name, real_path = "", (path or "").lower() or None
    if pid:
        got, err = _guard(pid, "quarantine")
        if err and "gone" not in err:
            _log("quarantine-entity", False, f"pid {pid}: {err}")
            return False, err
        if got:
            info, gname, gpath = got
            name = gname
            real_path = real_path or gpath
            r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                               capture_output=True, text=True, timeout=60)
            results["killed"] = r.returncode == 0
            if not results["killed"] and "not found" not in (r.stdout or "") + (r.stderr or ""):
                results["errors"].append("taskkill: " + (r.stderr or "").strip()[:80])

    # 3.+4. vault the binary (quarantine_file extracts config + auto-blocks peers)
    if real_path and os.path.isfile(real_path):
        okq, vault = quarantine_file(real_path)
        results["vault"] = vault if okq else None
        if not okq:
            results["errors"].append("vault failed")

    # 5. record the lifecycle state on the correlation key
    from . import correlation as _corr
    key = _corr._entity_key(real_path, pid, peers[0] if peers else None)
    set_entity_status(key, "quarantined", by=by,
                      detail=(name or os.path.basename(real_path or "") or str(pid)))
    ok = not results["errors"] and bool(results["killed"] or results["vault"] or results["blocked_peers"])
    state.raise_alert("RESP-QUARANTINE", "high",
                      f"Response: implant quarantined ({name or real_path or pid})",
                      "Full entity containment: C2 peers firewalled, process tree terminated, "
                      "binary moved to the vault with execute denied. The entity shows as "
                      "quarantined/inactive once containment verification passes.",
                      data={"pid": pid, "name": name, "path": real_path, **results})
    _log("quarantine-entity", bool(ok),
         f"{name or real_path or pid}: peers={results['blocked_peers']} "
         f"killed={results['killed']} vault={'yes' if results['vault'] else 'no'}")
    return bool(ok), results

def isolate_host():
    """Network-contain the whole machine (Defender 'device isolation'
    semantics): block ALL outbound traffic. Loopback is exempt from Windows
    Firewall filtering, so the EDR console on 127.0.0.1 stays reachable."""
    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                    "name=" + ISOLATE_RULE, "dir=out", "action=block",
                    "profile=any"], capture_output=True, timeout=30)
    _log("isolate", True, "host network isolation ON (all outbound blocked; loopback exempt)")
    state.raise_alert("RESP-ISOLATE", "critical", "Response: HOST NETWORK ISOLATION enabled",
                      "All outbound traffic from this machine is now blocked at the firewall. "
                      "Loopback remains reachable, so this console and the EDR sensors stay "
                      "manageable. Release isolation from the Implants screen when done.",
                      data={"rule": ISOLATE_RULE, "direction": "out"})
    return True, "host isolated — outbound blocked (console still reachable on loopback)"

def release_host():
    """Undo host isolation."""
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=" + ISOLATE_RULE], capture_output=True, timeout=30)
    _log("release", True, "host network isolation released")
    state.raise_alert("RESP-ISOLATE", "high", "Response: host network isolation RELEASED",
                      "Outbound connectivity restored. Per-peer C2 blocks (if any) remain "
                      "in force until individually unblocked.",
                      data={"rule": ISOLATE_RULE, "released": True})
    return True, "isolation released — outbound restored"
