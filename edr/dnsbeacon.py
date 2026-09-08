"""DNS beacon detection over the Windows DNS Client operational channel.

Realm imix and similar implants beacon over DNS (TXT/A/AAAA). The DNS Client
channel (event 3006/3008) gives (process, queried name, time) - we run the
same jitter-tolerant periodicity analysis as network.py, keyed on
(pid, registered domain) so round-robin subdomains don't defeat it.
"""
import time, re, statistics
from . import state

MIN_OBS = 6
JITTER_TOL = 0.35

_flows = {}      # (pid, domain) -> [timestamps]
_flagged = set()

def note_query(pid, qname, ts=None):
    ts = ts or time.time()
    # keep only the last two labels (registered domain) to defeat RR subdomains
    labels = (qname or "").rstrip(".").split(".")
    dom = ".".join(labels[-2:]) if len(labels) >= 2 else (qname or "?")
    key = (pid, dom.lower())
    s = _flows.setdefault(key, [])
    if not s or ts - s[-1] > 2.0:
        s.append(ts)
    del s[:-40]

def detect():
    for (pid, dom), ts in _flows.items():
        if (pid, dom) in _flagged or len(ts) < MIN_OBS:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        if len(gaps) < MIN_OBS - 1 or min(gaps) < 4:
            continue
        mean = statistics.mean(gaps)
        if mean <= 0:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv <= JITTER_TOL:
            _flagged.add((pid, dom))
            rec = state.norm_event("dns", "network", "critical",
                                   f"DNS beacon: pid {pid} querying {dom} every ~{mean:.1f}s",
                                   {"pid": pid, "peer": dom, "interval": round(mean, 1),
                                    "jitter_cv": round(cv, 3), "obs": len(ts)})
            state.stats["beacons"] += 1
            state.raise_alert("DNS-BEACON", "critical",
                              f"DNS beacon cadence: {dom}",
                              f"{len(ts)} queries from pid {pid} to *.{dom} at a near-constant "
                              f"~{mean:.1f}s interval (gap CV {cv:.2f}). Fixed-interval DNS "
                              "resolution by a non-resolver process is the imix DNS-transport "
                              "beacon profile (TXT/A/AAAA tunneling).",
                              event=rec, data={"pid": pid, "peer": dom, "interval": round(mean, 1)})
