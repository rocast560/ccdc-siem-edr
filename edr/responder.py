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
        shutil.move(path, dest)
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
    _log("quarantine", True, f"{path} -> {dest}")
    state.raise_alert("RESP-QUAR", "high", f"Response: quarantined {os.path.basename(path)}",
                      "Analyst-initiated quarantine: file moved to the EDR vault with execute "
                      "rights denied; origin recorded in the quarantine manifest for restore.",
                      data={"path": path, "vault": dest, "sha16": sha})
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
