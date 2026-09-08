"""Shared EDR state: event store, alert store, thread-safe ring buffers."""
import threading, time, json, collections

LOCK = threading.RLock()

events = collections.deque(maxlen=5000)   # normalized telemetry records
alerts = collections.deque(maxlen=1000)   # rule hits / auditor diffs
scans  = collections.deque(maxlen=1000)   # signature scan results

stats = {
    "started": time.time(),
    "events_total": 0,
    "alerts_total": 0,
    "processes_tracked": 0,
    "files_scanned": 0,
    "signatures_hit": 0,
    "persistence_diffs": 0,
    "beacons": 0,
    "eventlog_records": 0,
    "kernel_trace": None,   # description of ETW/kernel source if active
    "sources": [],
}

rule_hits = {}        # rule_id -> lifetime hit count
rule_enabled = {}     # rule_id -> bool (populated by rules module on import)
_seq = [0]

def norm_event(source, kind, severity, title, data):
    """Create a normalized telemetry record (the SIEM ingest shape)."""
    with LOCK:
        _seq[0] += 1
        rec = {
            "id": _seq[0],
            "ts": time.time(),
            "source": source,          # sensor that produced it
            "kind": kind,              # process|file|registry|eventlog|network|audit
            "severity": severity,      # info|low|medium|high|critical
            "title": title,
            "data": data,
        }
        events.append(rec)
        stats["events_total"] += 1
        return rec

def raise_alert(rule_id, severity, title, why, event=None, data=None):
    with LOCK:
        _seq[0] += 1
        a = {
            "id": _seq[0],
            "ts": time.time(),
            "rule": rule_id,
            "severity": severity,
            "title": title,
            "why": why,               # "why this fired" panel payload
            "event": event,
            "data": data or {},
            "status": "new",
        }
        alerts.append(a)
        stats["alerts_total"] += 1
        rule_hits[rule_id] = rule_hits.get(rule_id, 0) + 1
        return a

def set_alert_status(alert_id, status):
    with LOCK:
        for a in alerts:
            if a["id"] == alert_id:
                a["status"] = status
                return True
    return False

def query_events(severity=None, source=None, kind=None, q=None, limit=300):
    """Filtered read of the event ring for the Log Explorer."""
    with LOCK:
        out = list(events)
    if severity:
        out = [e for e in out if e["severity"] == severity]
    if source:
        out = [e for e in out if e["source"] == source]
    if kind:
        out = [e for e in out if e["kind"] == kind]
    if q:
        ql = q.lower()
        out = [e for e in out if ql in e["title"].lower() or ql in json.dumps(e["data"]).lower()]
    return out[-limit:]

def snapshot(limit=50, alerts_limit=None):
    with LOCK:
        return {
            "stats": dict(stats),
            "events": list(events)[-limit:],
            "alerts": list(alerts)[-(alerts_limit or len(alerts)):],
            "scans": list(scans)[-limit:],
            "rule_hits": dict(rule_hits),
            "rule_enabled": dict(rule_enabled),
        }
