"""EDR/SIEM backend + sensor orchestration + web console server.

Run:  python -m edr            (from the repo root)
Console: http://127.0.0.1:8420  (live five-screen console, all data from sensors)
"""
import json, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import (state, rules, signatures, persistence, processes, eventlog, network,
               responder, lsass, dotnet, dnsbeacon, linux_sensor, icmp, memscan)

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
                              "linux-packet-sockets", "icmp-cadence", "process-memory-scan"]
    state.stats["last_cycle"] = time.time()
    eventlog.enable_audit_sources()
    eventlog.try_kernel_trace()
    dotnet_ok = dotnet.start()
    state.norm_event("sensor", "audit", "info", ".NET ETW loader session " +
                     ("started" if dotnet_ok else "unavailable"), {})
    persistence.take_baseline()
    t_proc = t_evt = t_net = t_audit = t_scan = t_lsass = t_dotnet = t_dns = t_linux = 0
    t_icmp = t_mem = 0
    while not stop.is_set():
        now = time.time()
        try:
            if now - t_proc >= 3:
                processes.poll_once(); t_proc = now
            if now - t_evt >= 3:
                eventlog.poll_channels(); t_evt = now
            if now - t_net >= 5:
                network.poll_once(); t_net = now
            if now - t_dns >= 10:
                dnsbeacon.detect(); t_dns = now
            if now - t_icmp >= 10:
                icmp.poll(); t_icmp = now
            if now - t_mem >= 60:
                memscan.scan_all(); t_mem = now
            if now - t_lsass >= 30:
                lsass.sweep(); t_lsass = now
            if now - t_dotnet >= 60:
                dotnet.poll(); t_dotnet = now
            if now - t_linux >= 10:
                linux_sensor.poll(); t_linux = now
            if now - t_audit >= 30:
                persistence.audit_cycle(); t_audit = now
            if now - t_scan >= 60:
                signatures.scan_dirs(); t_scan = now
            state.stats["last_cycle"] = now
        except Exception as e:
            state.norm_event("sensor", "audit", "low", "Sensor cycle error", {"error": str(e)})
        stop.wait(1.0)

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
            with open(LIVEJS, "rb") as f:
                js = f.read()
            html = html.replace(b"</body>", b"<script>" + js + b"</script></body>", 1)
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
            elif action == "quarantine":
                ok, msg = responder.quarantine_file(body.get("path"))
            elif action == "block":
                ok, msg = responder.block_ip(body.get("peer"))
            elif action == "unblock":
                ok, msg = responder.unblock_ip(body.get("peer"))
            else:
                ok, msg = False, "unknown action"
            self._send(200, {"ok": ok, "message": msg})
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
