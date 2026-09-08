"""ICMP tunnel/beacon detection.

Windows exposes no per-peer ICMP table without a driver, but `netstat -s`
gives kernel ICMP counters. A process sending ICMP echoes at a near-constant
interval (imix ICMP transport, ICMP C2 tunnels) shows up as counter deltas
with beacon-like periodicity - same jitter-tolerant analysis as the TCP/DNS
cadence detectors, keyed on the counter itself. Peer attribution needs the
kernel ETW trace; that is documented as backlog in the report.
"""
import re, subprocess, time, statistics
from . import state

MIN_OBS = 6
JITTER_TOL = 0.35

RX = re.compile(r"^\s*(Echos|Echo Replies)\s+(\d+)\s+(\d+)\s*$", re.M)

_history = []          # (ts, total_echo_activity)
_flagged = False

def _icmp_totals():
    out = subprocess.run(["netstat", "-s"], capture_output=True,
                         text=True, errors="replace", timeout=30).stdout or ""
    sec = out.split("ICMPv4 Statistics", 1)
    body = sec[1].split("ICMPv6", 1)[0] if len(sec) > 1 else ""
    total = 0
    for m in RX.finditer(body):
        total += int(m.group(2)) + int(m.group(3))    # received + sent
    return total

def poll():
    global _flagged
    now = time.time()
    try:
        total = _icmp_totals()
    except Exception:
        return
    _history.append((now, total))
    del _history[:-60]
    if _flagged or len(_history) < MIN_OBS + 1:
        return
    # only consider windows where activity actually increased (echoes flowing)
    deltas = [(b[0] - a[0], b[1] - a[1]) for a, b in zip(_history, _history[1:]) if b[1] > a[1]]
    if len(deltas) < MIN_OBS:
        return
    gaps = [g for g, _ in deltas]
    if min(gaps) < 4:
        return
    mean = statistics.mean(gaps)
    if mean <= 0:
        return
    cv = statistics.pstdev(gaps) / mean
    if cv <= JITTER_TOL:
        _flagged = True
        rec = state.norm_event("icmp", "network", "high",
                               "ICMP echo activity at near-constant ~%.1fs interval" % mean,
                               {"peer": "icmp-echo-counters", "interval": round(mean, 1),
                                "jitter_cv": round(cv, 3), "obs": len(deltas)})
        state.stats["beacons"] += 1
        state.raise_alert(
            "ICMP-BEACON", "high", "Periodic ICMP echo activity (tunnel/covert-channel profile)",
            "Kernel ICMP counters increased in %d bursts at a near-constant ~%.1fs interval "
            "(gap CV %.2f). Steady fixed-interval ICMP echo traffic is the imix ICMP-transport "
            "beacon profile; ordinary human/OS ping traffic is bursty, not periodic. Per-peer "
            "attribution requires the kernel ETW trace (documented backlog)."
            % (len(deltas), mean, cv),
            event=rec, data={"interval": round(mean, 1)})
