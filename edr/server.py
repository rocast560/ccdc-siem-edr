"""EDR/SIEM backend + sensor orchestration + web console server.

Run:  python -m edr            (from the repo root)
Console: http://127.0.0.1:8420  (live five-screen console, all data from sensors)
"""
import json, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import (state, rules, signatures, persistence, processes, eventlog, network,
               responder, lsass, dotnet, dnsbeacon, linux_sensor, icmp, memscan,
               modules, hooks, pipes, memmap, handles, intel, correlation)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONSOLE = os.path.join(ROOT, "ccdc-edr-console.html")     # original edr-ui-only design
LIVEJS = os.path.join(HERE, "console_live.js")            # wiring that makes it functional
PORT = 8420

# ---------------------------------------------------------------- sensor loop

def sensor_loop(stop: threading.Event):
    state.stats["sources"] = ["wmi-process-poll", "windows-eventlog", "persistence-auditor",
                              "signature-scanner", "netstat-flows+beacon-cadence",
                              "dotnet-etw-loader", "lsass-handle-sweep", "dns-client-beacons",
                              "linux-packet-sockets", "icmp-cadence", "process-memory-scan",
                              "module-walk", "ntdll-integrity+thread-scan", "named-pipes",
                              "memmap-rwx/syscall-stubs", "cross-process-handles"]
    state.stats["last_cycle"] = time.time()
    eventlog.enable_audit_sources()
    eventlog.try_kernel_trace()
    dotnet_ok = dotnet.start()
    state.norm_event("sensor", "audit", "info", ".NET ETW loader session " +
                     ("started" if dotnet_ok else "unavailable"), {})
    persistence.take_baseline()
    # one thread per sensor: a slow pass (audit + eventlog + memmap together)
    # must not stretch the fast cadences (netstat 5s) that beacon detection
    # depends on - sequential scheduling stretched them to 30-60s under load
    jobs = [
        (3,   "process-poll",  lambda: processes.poll_once()),
        (3,   "eventlog",      lambda: eventlog.poll_channels()),
        (5,   "netstat",       lambda: network.poll_once()),
        (10,  "dnsbeacon",     lambda: dnsbeacon.detect()),
        (10,  "icmp",          lambda: icmp.poll()),
        (30,  "lsass",         lambda: lsass.sweep()),
        (45,  "dotnet",        lambda: dotnet.poll()),
        (10,  "linux",         lambda: linux_sensor.poll()),
        (30,  "audit",         lambda: persistence.audit_cycle()),
        (60,  "scan",          lambda: signatures.scan_dirs()),
        (60,  "memscan",       lambda: memscan.scan_all()),
        (45,  "modules",       lambda: modules.poll()),
        (90,  "hooks",         lambda: hooks.poll()),
        (20,  "pipes",         lambda: pipes.poll()),
        (75,  "memmap",        lambda: memmap.poll()),
        (45,  "handles",       lambda: handles.sweep()),
    ]

    def run_sensor(interval, name, fn):
        while not stop.is_set():
            t0 = time.time()
            try:
                fn()
                state.stats["last_cycle"] = time.time()
            except Exception as e:
                state.norm_event("sensor", "audit", "low",
                                 "Sensor error: " + name, {"error": str(e)[:200]})
            elapsed = time.time() - t0
            stop.wait(max(0.5, interval - elapsed))

    threads = []
    for interval, name, fn in jobs:
        th = threading.Thread(target=run_sensor, args=(interval, name, fn),
                              daemon=True, name="sensor-" + name)
        th.start()
        threads.append(th)
        time.sleep(0.3)              # stagger startup
    for th in threads:
        th.join()

def watchdog(stop: threading.Event):
    """Alert if the sensor loop stalls (killed/blinded sensors)."""
    while not stop.is_set():
        time.sleep(15)
        last = state.stats.get("last_cycle", 0)
        if last and time.time() - last > 60:
            state.raise_alert("SENSOR-WATCHDOG", "critical", "Sensor loop stalled",
                              "The EDR sensor loop has not completed a cycle in over 60 seconds. "
                              "Sensors may have been killed or suspended - an EDR-tamper signal.",
                              data={"last_cycle_age_s": round(time.time() - last, 1)})

# ---------------------------------------------------------------- http

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/console", "/index.html"):
            with open(CONSOLE, "rb") as f:
                html = f.read()
            inject = b""
            for jsfile in (LIVEJS, os.path.join(HERE, "beacon_triage.js"),
                           os.path.join(HERE, "implants.js")):
                try:
                    with open(jsfile, "rb") as f:
                        inject += b"<script>" + f.read() + b"</script>"
                except OSError:
                    pass
            html = html.replace(b"</body>", inject + b"</body>", 1)
            self._send(200, html, "text/html; charset=utf-8")
        elif u.path == "/api/state":
            snap = state.snapshot(limit=100, alerts_limit=1000)
            snap["rules"] = rules.list_rules()
            self._send(200, snap)
        elif u.path == "/api/events":
            self._send(200, state.query_events(
                severity=(q.get("severity") or [None])[0],
                source=(q.get("source") or [None])[0],
                kind=(q.get("kind") or [None])[0],
                q=(q.get("q") or [None])[0],
                limit=min(int((q.get("limit") or [300])[0]), 1000)))
        elif u.path == "/api/rules":
            rl = rules.list_rules()
            for r in rl:
                r["enabled"] = state.rule_enabled.get(r["id"], True)
                r["hits"] = state.rule_hits.get(r["id"], 0)
            self._send(200, rl)
        elif u.path == "/api/scans":
            with state.LOCK:
                self._send(200, list(state.scans)[-200:])
        elif u.path == "/api/cadence":
            self._send(200, network.cadence_snapshot())
        elif u.path == "/api/implants":
            self._send(200, correlation.compute())
        elif u.path == "/api/intel":
            ip = (q.get("ip") or [""])[0]
            if not ip:
                self._send(400, {"error": "ip parameter required"})
                return
            try:
                self._send(200, intel.enrich(ip, force=(q.get("force") or ["0"])[0] == "1"))
            except Exception as e:
                self._send(200, {"ip": ip, "error": str(e)})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if u.path == "/api/baseline":
            inv = persistence.take_baseline()
            self._send(200, {"ok": True, "baseline": {k: (len(v) if hasattr(v, "__len__") else v)
                                                      for k, v in inv.items() if k != "run"} |
                            {"run_values": sum(len(x) for x in inv["run"].values())}})
        elif u.path == "/api/scan":
            cnt = signatures.scan_dirs()
            self._send(200, {"ok": True, "files_considered": cnt})
        elif u.path == "/api/audit":
            findings = persistence.audit_cycle()
            self._send(200, {"ok": True, "findings": findings})
        elif u.path == "/api/alerts/status":
            ok = state.set_alert_status(int(body.get("id", 0)), body.get("status", "new"))
            self._send(200 if ok else 404, {"ok": ok})
        elif u.path == "/api/rules/toggle":
            rid = body.get("id")
            if rid in state.rule_enabled:
                state.rule_enabled[rid] = bool(body.get("enabled", True))
                self._send(200, {"ok": True, "id": rid, "enabled": state.rule_enabled[rid]})
            else:
                self._send(404, {"ok": False, "error": "unknown rule"})
        elif u.path == "/api/test":
            text = str(body.get("text", ""))
            sig_hits = [{"rule": h["id"], "name": h["name"], "severity": h["severity"],
                         "matched_field": "signature-scan"} for h in signatures.scan_bytes(text.encode())]
            self._send(200, {"matches": rules.test_sample(text) + sig_hits})
        elif u.path == "/api/respond":
            action = body.get("action")
            if action == "kill":
                ok, msg = responder.kill_process(body.get("pid"))
            elif action == "suspend":
                ok, msg = responder.suspend_process(body.get("pid"))
            elif action == "resume":
                ok, msg = responder.resume_process(body.get("pid"))
            elif action == "quarantine":
                ok, msg = responder.quarantine_file(body.get("path"))
            elif action == "block":
                ok, msg = responder.block_ip(body.get("peer"))
            elif action == "unblock":
                ok, msg = responder.unblock_ip(body.get("peer"))
            elif action == "quarantine_entity":
                ok, msg = responder.quarantine_entity(body.get("pid"),
                                                      peers=body.get("peers"),
                                                      path=body.get("path"))
            elif action == "kill_tree":
                ok, msg = responder.kill_tree(body.get("pid"))
            elif action == "isolate":
                ok, msg = responder.isolate_host()
            elif action == "release":
                ok, msg = responder.release_host()
            elif action == "entity_status":
                ok, msg = responder.set_entity_status(body.get("key"),
                                                      body.get("status") or "monitoring")
            elif action == "protect":
                state.protect_mode = bool(body.get("enabled", True))
                state.norm_event("responder", "audit", "high",
                                 "Protect mode " + ("enabled — confirmed implants auto-quarantined"
                                                    if state.protect_mode else "disabled"),
                                 {"protect_mode": state.protect_mode})
                self._send(200, {"ok": True, "protect_mode": state.protect_mode})
                return
            else:
                ok, msg = False, "unknown action"
            self._send(200, {"ok": ok, "message": msg})
        elif u.path == "/api/implants/verify":
            key = body.get("key")
            if not key:
                self._send(400, {"error": "key required"})
                return
            self._send(200, correlation.verify_containment(key))
        else:
            self._send(404, {"error": "not found"})

def main():
    stop = threading.Event()
    threading.Thread(target=sensor_loop, args=(stop,), daemon=True).start()
    threading.Thread(target=watchdog, args=(stop,), daemon=True).start()
    # On Windows SO_REUSEADDR would silently double-bind the port, leaving a
    # stale instance serving old code; refuse the overlap instead.
    ThreadingHTTPServer.allow_reuse_address = False
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"CCDC EDR/SIEM console: http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    finally:
        stop.set()

if __name__ == "__main__":
    main()
