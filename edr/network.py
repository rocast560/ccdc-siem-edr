"""Network sensor: netstat flow table + beacon-cadence (periodicity) detection
+ non-service listener detection (imix tcp_bind transport).

Per (pid, peer) we keep connection timestamps; a peer whose inter-arrival gaps
stay near-constant (low coefficient of variation) across >= MIN_OBS samples is
flagged as a beacon, tolerating C2 jitter up to JOITTER_TOL.
"""
import subprocess, re, time, statistics
from . import state, rules

MIN_OBS = 6
JITTER_TOL = 0.35      # allow up to 35% gap variation (imix jitter is 0.0-1.0 of interval)
LOOPBACK = ("127.", "::1")

_flows = {}            # (pid, peer) -> list of first-seen timestamps
_flagged = set()
_listeners = {}        # (pid, port) -> alert-raised marker
KNOWN_SERVICE_PORTS = {80, 443, 445, 139, 135, 3389, 5985, 5986, 22, 21, 25, 53,
                       1433, 3306, 5432, 8080, 8443, 47001, 49664, 49665, 49666}
SERVICE_IMG_PREFIXES = (r"c:\windows", r"c:\program files")

def check_listeners():
    """Flag processes LISTENING on non-standard ports from non-service paths -
    the imix tcp_bind inverted transport (agent chains await inbound connects)
    and netcat-style backdoors."""
    r = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True,
                       text=True, errors="replace", timeout=30)
    for line in (r.stdout or "").splitlines():
        if "LISTENING" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            pid = int(parts[4])
            port = int(parts[1].rsplit(":", 1)[1])
        except ValueError:
            continue
        if port in KNOWN_SERVICE_PORTS or (pid, port) in _listeners or pid in (0, 4):
            continue
        _listeners[(pid, port)] = True
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-CimInstance Win32_Process -Filter 'ProcessId=%d' | "
                              "Select-Object Name,ExecutablePath | ConvertTo-Json -Compress" % pid],
                             capture_output=True, text=True, errors="replace", timeout=30).stdout
        import json
        try:
            info = json.loads(out) if out.strip() else None
        except json.JSONDecodeError:
            info = None
        name = (info or {}).get("Name") or "?"
        path = ((info or {}).get("ExecutablePath") or "").lower()
        if any(path.startswith(p) for p in SERVICE_IMG_PREFIXES if p):
            continue                        # signed/installed service binary
        rec = state.norm_event("network", "network", "high",
                               "Non-service listener: %s (pid %d) on port %d" % (name, pid, port),
                               {"pid": pid, "peer": "0.0.0.0:%d" % port, "port": port,
                                "path": path, "cmdline": path or name})
        state.raise_alert(
            "NET-LISTENER", "high", "%s listening on port %d" % (name, port),
            "A process running from a non-service path is accepting inbound TCP on a "
            "non-standard port. This is the imix 'tcp_bind' inverted-transport posture "
            "(the implant listens for operator/inbound chaining) and the netcat-backdoor "
            "pattern. Legitimate listeners run from Windows/Program Files on expected ports.",
            event=rec, data={"pid": pid, "port": port, "path": path})

ROW = re.compile(r"^\s*\S+\s+(\S+)\s+(\S+)\s+\S+\s+(\d+)")

def poll_once():
    r = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, errors="replace", timeout=30)
    now = time.time()
    rows = []
    for line in (r.stdout or "").splitlines():
        m = ROW.match(line)
        if not m:
            continue
        local, remote, pid = m.group(1), m.group(2), int(m.group(3))
        if remote.startswith(("0.0.0.0", "[::]", "*")):
            continue                       # listening/unconnected socket row, not a peer
        peer = remote.rsplit(":", 1)[0]
        rows.append((pid, peer, remote))
        key = (pid, peer)
        ts = _flows.setdefault(key, [])
        if not ts or now - ts[-1] > 2.0:      # debounce concurrent connections
            ts.append(now)
        del ts[:-40]
    # drop vanished flows
    live = {(p, pe) for p, pe, _ in rows}
    for k in [k for k in _flows if k not in live]:
        if now - (_flows[k][-1] if _flows[k] else 0) > 60:
            del _flows[k]
    detect_beacons()
    check_listeners()
    return len(rows)

def cadence_snapshot():
    """Beacon cadence series for the console's periodicity plot."""
    out = []
    for (pid, peer), ts in _flows.items():
        if (pid, peer) in _flagged and len(ts) >= 3:
            gaps = [round(b - a, 1) for a, b in zip(ts, ts[1:])]
            mean = sum(gaps) / len(gaps)
            out.append({"pid": pid, "peer": peer, "interval": round(mean, 1),
                        "obs": len(ts), "series": [round(t - ts[0], 1) for t in ts],
                        "gaps": gaps})
    return out

def detect_beacons():
    for (pid, peer), ts in _flows.items():
        if (pid, peer) in _flagged or len(ts) < MIN_OBS:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        if len(gaps) < MIN_OBS - 1 or min(gaps) < 4:
            continue
        mean = statistics.mean(gaps)
        if mean <= 0:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv <= JITTER_TOL:
            _flagged.add((pid, peer))
            loop = peer.startswith(LOOPBACK)
            rec = state.norm_event("network", "network", "critical",
                                   f"Beacon cadence: pid {pid} -> {peer} every ~{mean:.1f}s",
                                   {"pid": pid, "peer": peer, "interval": round(mean, 1),
                                    "jitter_cv": round(cv, 3), "obs": len(ts), "loopback": loop})
            state.stats["beacons"] += 1
            state.raise_alert(
                "NET-BEACON", "critical" if not loop else "high",
                f"Periodic beacon: {peer}",
                f"{len(ts)} connections from pid {pid} to {peer} at a near-constant "
                f"~{mean:.1f}s interval (gap CV {cv:.2f}, tolerant to {int(JITTER_TOL*100)}% jitter). "
                "Fixed-interval + jitter callback is the C2 profile of imix/Havoc/Beacon. "
                + ("(lab loopback peer)" if loop else ""),
                event=rec, data={"pid": pid, "peer": peer, "interval": round(mean, 1)})
