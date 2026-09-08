/* Live wiring + UI redesign for the CCDC-EDR console.
   The server serves ccdc-edr-console.html and injects this file before </body>.
   The page's own script switches which .pg-screen is active and keeps the navbar;
   this file keeps that navbar (and now live-updates its counts), throws away the
   static sample body of each screen, and renders a clean, functional analyst
   surface from the live sensor API. Same endpoints, same 2.5s cadence. */
(function () {
  "use strict";

  var $  = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  var SEV = {
    critical: { c: "#CD4246", label: "critical" },
    high:     { c: "#EC9A3C", label: "high" },
    medium:   { c: "#FBD065", label: "medium" },
    low:      { c: "#3FA6DA", label: "low" },
    info:     { c: "#5F6B7C", label: "info" }
  };
  var ORDER = ["critical", "high", "medium", "low", "info"];
  var sevColor = function (s) { return (SEV[s] || SEV.info).c; };

  var CACHE = { state: null, events: [], cadence: [], rules: [] };
  var LASTCRIT = -1;          // for new-critical flash
  var CONNECTED = true;

  /* ---------------------------------------------------------------- helpers */
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }
  function mk(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function fmtT(ts) { return new Date(ts * 1000).toTimeString().slice(0, 8); }
  function clockUTC(d) {
    d = d || new Date();
    var p = function (n) { return (n < 10 ? "0" : "") + n; };
    return d.getUTCFullYear() + "-" + p(d.getUTCMonth() + 1) + "-" + p(d.getUTCDate()) +
           " " + p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + ":" + p(d.getUTCSeconds()) + "Z";
  }
  function dur(sec) {
    sec = Math.max(0, Math.floor(sec));
    var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
    if (h) return h + "h " + m + "m";
    if (m) return m + "m";
    return sec + "s";
  }
  function getJSON(url, post, body) {
    return fetch(url, post ? {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    } : undefined).then(function (r) { return r.json(); });
  }
  function sevBadge(sev) {
    var b = mk("span", "sev", (SEV[sev] || SEV.info).label);
    b.style.background = sevColor(sev);
    return b;
  }
  function dot(sev) {
    var d = mk("span", "lv-dot");
    d.style.background = sevColor(sev);
    return d;
  }
  function btn(label, kind, onclick) {
    var b = mk("button", "btn" + (kind ? " btn-" + kind : ""), label);
    b.type = "button";
    if (onclick) b.onclick = onclick;
    return b;
  }
  function pill(text, color, bg) {
    var p = mk("span", "lv-pill", text);
    p.style.color = color;
    p.style.background = bg;
    return p;
  }
  function empty(txt) { return mk("div", "lv-empty", txt); }

  /* panel scaffold: header (label + optional right meta) over a scroll body */
  function panel(label, opts) {
    opts = opts || {};
    var p = mk("div", "lv-panel");
    if (opts.grow) p.style.flex = opts.grow;
    var head = mk("div", "lv-phead");
    head.appendChild(mk("span", null, label));
    var meta = mk("span", "lv-meta");
    head.appendChild(meta);
    var body = mk("div", "lv-pbody" + (opts.pad0 ? " pad0" : ""));
    p.appendChild(head); p.appendChild(body);
    p._label = head.firstChild; p._meta = meta; p._body = body;
    p.setLabel = function (t) { head.firstChild.textContent = t; };
    p.setMeta = function (t) { meta.textContent = t == null ? "" : t; };
    return p;
  }
  function region(body) {
    var r = mk("div", "lv-region");
    body.appendChild(r);
    return r;
  }
  function col(flex) {
    var c = mk("div", "lv-col");
    c.style.flex = flex;
    return c;
  }

  /* ---------------------------------------------------------------- styles */
  (function injectStyle() {
    if ($("#lv-style")) return;
    var css = [
      ".lv-body{flex:1;display:flex;flex-direction:column;min-height:0;background:var(--well)}",
      /* status / threat strip */
      ".lv-strip{flex:none;display:flex;align-items:center;gap:14px;height:32px;padding:0 14px;",
      "background:#12161b;border-bottom:1px solid #0b0e11;font:11.5px/1 var(--mono);color:var(--fg3);",
      "transition:background .5s}",
      ".lv-strip b{color:var(--fg);font-weight:600}",
      ".lv-strip.flash{background:rgba(205,66,70,.22)}",
      ".lv-live{width:8px;height:8px;border-radius:50%;background:var(--green5);flex:none;animation:lvpulse 1.8s infinite}",
      ".lv-live.off{background:#CD4246;animation:none}",
      "@keyframes lvpulse{0%{box-shadow:0 0 0 0 rgba(114,202,155,.5)}70%{box-shadow:0 0 0 6px rgba(114,202,155,0)}100%{box-shadow:0 0 0 0 rgba(114,202,155,0)}}",
      ".lv-sp{flex:1}",
      ".lv-pill{display:inline-flex;align-items:center;gap:6px;height:18px;padding:0 9px;border-radius:9px;",
      "font:600 10.5px/1 var(--ui);letter-spacing:.02em;white-space:nowrap}",
      /* regions + panels */
      ".lv-region{flex:1;display:flex;gap:12px;min-height:0;padding:12px;overflow:hidden}",
      ".lv-col{display:flex;flex-direction:column;gap:12px;min-height:0;min-width:0;overflow:auto}",
      ".lv-panel{background:var(--panel);border:1px solid var(--line);border-radius:3px;display:flex;",
      "flex-direction:column;min-height:0;overflow:hidden}",
      ".lv-phead{flex:none;display:flex;align-items:center;gap:8px;height:30px;padding:0 12px;",
      "border-bottom:1px solid var(--line);font:600 10px/1 var(--ui);letter-spacing:.09em;",
      "text-transform:uppercase;color:var(--fg4);white-space:nowrap;overflow:hidden}",
      ".lv-phead>span:first-child{overflow:hidden;text-overflow:ellipsis}",
      ".lv-meta{margin-left:auto;font:500 10.5px var(--mono);color:var(--fg4);text-transform:none;",
      "letter-spacing:0;flex:none}",
      ".lv-pbody{padding:10px 12px;display:flex;flex-direction:column;gap:8px;overflow:auto;min-height:0}",
      ".lv-pbody.pad0{padding:0}",
      ".lv-empty{color:var(--fg4);font-style:italic;padding:16px 12px;font:12px var(--mono)}",
      /* kpi tiles */
      ".lv-tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;flex:none}",
      ".lv-tile{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--fg4);",
      "border-radius:3px;padding:9px 12px;display:flex;flex-direction:column;gap:4px}",
      ".lv-tile .n{font:600 25px/1 var(--mono);color:var(--fg);font-variant-numeric:tabular-nums}",
      ".lv-tile .l{font:600 9px/1 var(--ui);letter-spacing:.09em;text-transform:uppercase;color:var(--fg4)}",
      /* table rows */
      ".lv-row{display:flex;align-items:center;gap:10px;height:27px;padding:0 8px;",
      "border-bottom:1px solid rgba(255,255,255,.045);font:11.5px var(--mono);color:#C5CBD3;",
      "white-space:nowrap;overflow:hidden}",
      ".lv-row>span{overflow:hidden;text-overflow:ellipsis}",
      ".lv-row.click{cursor:pointer}",
      ".lv-row.click:hover{background:rgba(76,144,240,.08)}",
      ".lv-dot{width:7px;height:7px;border-radius:50%;flex:none}",
      ".lv-t{color:var(--fg4)}",
      /* facets */
      ".lv-facet{display:flex;align-items:center;gap:8px;padding:3px 4px;cursor:pointer;font:11.5px var(--mono)}",
      ".lv-facet:hover{background:rgba(255,255,255,.03)}",
      ".lv-facet .nm{flex:0 0 78px;overflow:hidden;text-overflow:ellipsis;color:#C5CBD3}",
      ".lv-facet.on .nm{color:var(--blue5);font-weight:600}",
      ".lv-facet .bar{flex:1;height:5px;background:var(--well);border-radius:3px;overflow:hidden}",
      ".lv-facet .bar>i{display:block;height:100%;background:var(--blue4)}",
      ".lv-facet.on .bar>i{background:var(--blue5)}",
      ".lv-facet .ct{flex:0 0 34px;text-align:right;color:var(--fg4);font-variant-numeric:tabular-nums}",
      /* inputs */
      ".lv-input{width:100%;height:28px;padding:0 9px;background:var(--well);border:1px solid #404854;",
      "border-radius:2px;color:var(--fg);font:12px var(--mono)}",
      ".lv-input:focus{outline:none;border-color:var(--blue4)}",
      ".lv-ta{width:100%;min-height:96px;padding:8px 9px;background:var(--well);border:1px solid #404854;",
      "border-radius:2px;color:var(--fg);font:12px var(--mono);resize:vertical}",
      ".lv-ta:focus{outline:none;border-color:var(--blue4)}",
      /* rule toggles */
      ".lv-rule{display:flex;align-items:center;gap:11px;padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.045);font:11.5px var(--mono)}",
      ".lv-rule:hover{background:rgba(255,255,255,.02)}",
      ".lv-sw{position:relative;width:30px;height:16px;border-radius:8px;flex:none;cursor:pointer;transition:background .15s}",
      ".lv-sw>i{position:absolute;top:2px;width:11px;height:11px;border-radius:50%;background:#fff;transition:left .15s}",
      ".lv-sw.on{background:var(--blue)} .lv-sw.on>i{left:16px}",
      ".lv-sw.off{background:var(--well);box-shadow:inset 0 0 0 1px var(--line)} .lv-sw.off>i{left:2px;background:#5F6B7C}",
      /* buttons row helper */
      ".lv-acts{display:flex;gap:6px;flex-wrap:wrap;align-items:center}",
      ".lv-actbtn{height:20px;padding:0 8px;font:600 10.5px var(--ui);border-radius:2px;border:none;cursor:pointer}",
      /* cards */
      ".lv-card{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--blue4);",
      "border-radius:3px;padding:9px 11px;display:flex;flex-direction:column;gap:5px}",
      ".lv-card .ttl{font:600 12.5px var(--ui);color:var(--fg)}",
      ".lv-card .sub{font:10.5px var(--mono);color:var(--fg4)}",
      ".lv-kv{display:flex;gap:10px;font:11.5px var(--mono);padding:2px 0}",
      ".lv-kv .k{flex:0 0 118px;color:var(--fg4)}",
      ".lv-kv .v{color:#C5CBD3;word-break:break-all}",
      ".lv-chips{display:flex;flex-wrap:wrap;gap:5px}",
      ".lv-chip{font:10.5px var(--mono);color:#C5CBD3;padding:2px 7px;border-radius:2px;",
      "background:var(--well);box-shadow:inset 0 0 0 1px var(--line)}",
      /* detail drawer */
      ".lv-drawer{position:fixed;top:82px;right:12px;bottom:44px;width:min(540px,42vw);z-index:60;",
      "background:var(--panel);border:1px solid var(--blue4);border-radius:3px;display:flex;flex-direction:column;",
      "box-shadow:0 8px 30px rgba(0,0,0,.5)}",
      ".lv-drawer .dh{flex:none;display:flex;align-items:center;gap:10px;height:34px;padding:0 12px;",
      "border-bottom:1px solid var(--line);font:600 11px var(--ui);letter-spacing:.06em;text-transform:uppercase;color:var(--fg2)}",
      ".lv-drawer .dx{margin-left:auto;cursor:pointer;color:var(--fg3);font-size:16px;line-height:1}",
      ".lv-drawer .dx:hover{color:var(--fg)}",
      ".lv-drawer pre{margin:0;padding:12px;overflow:auto;font:11px/1.5 var(--mono);color:#C5CBD3;white-space:pre-wrap;word-break:break-word}",
      ".lv-sub{font:600 9px/1 var(--ui);letter-spacing:.09em;text-transform:uppercase;color:var(--fg4);margin:2px 0}",
      ".lv-mut{color:var(--fg4);font:11px var(--mono)}"
    ].join("");
    var st = mk("style"); st.id = "lv-style"; st.textContent = css;
    document.head.appendChild(st);
  })();

  /* ---------------------------------------------------------------- locate views, keep navbar */
  var views = $$(".pg-screen");
  if (views.length < 5) return;                       // not the console sheet
  var BODY = [null, null, null, null, null];
  var NAV = [];                                       // per-view cached navbar live nodes

  views.slice(0, 5).forEach(function (view, i) {
    var scr = view.querySelector(".scr");
    if (!scr) return;
    var navbar = scr.firstElementChild;

    /* index the navbar's stale nodes so we can drive them live */
    var nav = { rules: null, clock: null, badge: null };
    $$(".mono", navbar).forEach(function (m) {
      var t = (m.textContent || "").trim();
      if (/\d+\s*\/\s*\d+\s*rules/i.test(t)) nav.rules = m;
      else if (/\d{4}-\d{2}-\d{2}.*z/i.test(t) || /:\d{2}z/i.test(t)) nav.clock = m;
    });
    var tag = navbar.querySelector(".tag");
    if (tag) nav.badge = tag;
    NAV[i] = nav;

    var body = mk("div", "lv-body");
    body.setAttribute("data-live-body", "1");
    scr.appendChild(body);
    BODY[i] = body;

    view._liveCleanup = function () {
      Array.prototype.forEach.call(scr.children, function (c) {
        if (c !== navbar && c.getAttribute("data-live-body") !== "1") c.remove();
      });
    };
    view._liveCleanup();
  });

  /* shared status/threat strip, one per screen body */
  var STRIPS = [];
  function buildStrip(body) {
    var s = mk("div", "lv-strip");
    var live = mk("span", "lv-live");
    var txt = mk("span");
    var crit = pill("0 critical", "#FFC7C9", "rgba(205,66,70,.22)");
    var high = pill("0 high", "#FBD9B5", "rgba(236,154,60,.20)");
    var sp = mk("span", "lv-sp");
    var upd = mk("span"); upd.style.color = "var(--fg4)";
    s.appendChild(live); s.appendChild(txt);
    s.appendChild(crit); s.appendChild(high);
    s.appendChild(sp); s.appendChild(upd);
    body.appendChild(s);
    var o = { el: s, live: live, txt: txt, crit: crit, high: high, upd: upd };
    STRIPS.push(o);
    return o;
  }

  function updateStrips(s) {
    var st = s.stats, al = s.alerts || [];
    var nc = 0, nh = 0, newc = 0;
    al.forEach(function (a) {
      if (a.status === "new") {
        if (a.severity === "critical") { nc++; newc++; }
        else if (a.severity === "high") { nh++; }
      }
    });
    var flash = LASTCRIT >= 0 && newc > LASTCRIT;
    LASTCRIT = newc;
    var when = clockUTC().slice(11);
    STRIPS.forEach(function (o) {
      o.txt.innerHTML = "<b>" + st.events_total.toLocaleString() + "</b> events &middot; " +
        "<b>" + st.alerts_total.toLocaleString() + "</b> alerts &middot; up <b>" +
        dur(Date.now() / 1000 - st.started) + "</b>";
      o.crit.textContent = nc + " critical"; o.crit.style.display = nc ? "" : "none";
      o.high.textContent = nh + " high"; o.high.style.display = nh ? "" : "none";
      o.live.className = "lv-live" + (CONNECTED ? "" : " off");
      o.upd.textContent = (CONNECTED ? "updated " : "disconnected · last ") + when;
      if (flash) {
        o.el.classList.add("flash");
        setTimeout(function () { o.el.classList.remove("flash"); }, 900);
      }
    });
  }

  /* ================================================================ 1 · DASHBOARD */
  var renderDash = (function () {
    var body = BODY[0]; if (!body) return function () {};
    buildStrip(body);
    var reg = region(body);
    var left = col("2"), right = col("1");
    reg.appendChild(left); reg.appendChild(right);

    var tiles = mk("div", "lv-tiles"); left.appendChild(tiles);

    var spark = panel("ingest volume — events / 10s", { grow: "0 0 auto" });
    var cv = mk("canvas"); cv.style.cssText = "width:100%;height:96px;display:block";
    spark._body.appendChild(cv);
    left.appendChild(spark);

    var triage = panel("triage queue — untriaged critical / high", { grow: "1 1 auto", pad0: true });
    left.appendChild(triage);

    var health = panel("sensor health", { grow: "0 0 auto" });
    right.appendChild(health);

    var actions = panel("response actions", { grow: "0 0 auto" });
    var arow = mk("div", "lv-acts");
    [["Run persistence audit", "primary", "/api/audit"],
     ["Force signature scan", "", "/api/scan"],
     ["Re-baseline", "danger", "/api/baseline"]].forEach(function (a) {
      arow.appendChild(btn(a[0], a[1], function () {
        if (a[2] === "/api/baseline" && !confirm("Re-arm the persistence baseline at the CURRENT machine state? Anything already present becomes trusted.")) return;
        getJSON(a[2], 1, {}).then(tick);
      }));
    });
    actions._body.appendChild(arow);
    actions._body.appendChild(mk("div", "lv-mut",
      "Audit diffs run keys, services, tasks, startup, WMI. Scan re-checks drop zones. Re-baseline resets the persistence T0."));
    right.appendChild(actions);

    function respondInline(a) {
      var box = mk("span", "lv-acts");
      box.style.marginLeft = "auto";
      var d = a.data || {}, ev = a.event || {};
      function add(label, color, post) {
        var b = mk("button", "lv-actbtn", label);
        b.style.color = "#fff"; b.style.background = color;
        b.onclick = function (e) {
          e.stopPropagation();
          getJSON("/api/respond", 1, post).then(function (r) {
            b.textContent = (r.ok ? "✓ " : "✗ ") + label;
            b.style.background = r.ok ? "#1C6E42" : "#8E292C";
            setTimeout(tick, 400);
          });
        };
        box.appendChild(b);
      }
      if (d.pid) add("kill " + d.pid, "#A82A2A", { action: "kill", pid: d.pid });
      if (d.peer) add("block", "#935610", { action: "block", peer: d.peer });
      var path = d.path || (ev.data && ev.data.path);
      if (path && /SIG-|IMPLANT|TEMP|WEBSHELL/.test(a.rule)) add("quarantine", "#634DBF", { action: "quarantine", path: path });
      return box;
    }

    return function (s) {
      var al = s.alerts || [], st = s.stats;
      var c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      al.forEach(function (a) { if (c[a.severity] != null) c[a.severity]++; });
      var newCount = al.filter(function (a) { return a.status === "new"; }).length;

      tiles.innerHTML = "";
      [["critical", c.critical, sevColor("critical")],
       ["high", c.high, sevColor("high")],
       ["medium", c.medium, sevColor("medium")],
       ["untriaged", newCount, newCount ? sevColor("critical") : "#738091"],
       ["events", st.events_total.toLocaleString(), "#4C90F0"],
       ["processes", st.processes_tracked, "#738091"],
       ["beacons", st.beacons, st.beacons ? sevColor("high") : "#738091"],
       ["persistence Δ", st.persistence_diffs, st.persistence_diffs ? sevColor("high") : "#738091"]]
      .forEach(function (t) {
        var el = mk("div", "lv-tile");
        el.style.borderLeftColor = t[2];
        var n = mk("div", "n", t[1]); n.style.color = /^#73/.test(t[2]) ? "var(--fg)" : t[2];
        el.appendChild(n);
        el.appendChild(mk("div", "l", t[0]));
        tiles.appendChild(el);
      });

      /* sparkline */
      var evs = s.events || [], now = Date.now() / 1000, buckets = new Array(30).fill(0);
      evs.forEach(function (e) { var b = Math.floor((now - e.ts) / 10); if (b >= 0 && b < 30) buckets[29 - b]++; });
      var ctx = cv.getContext("2d");
      var W = cv.width = cv.clientWidth || 600, H = cv.height = 96;
      ctx.clearRect(0, 0, W, H);
      ctx.strokeStyle = "#20262d"; ctx.beginPath(); ctx.moveTo(0, H - 14.5); ctx.lineTo(W, H - 14.5); ctx.stroke();
      var max = Math.max.apply(null, buckets.concat([1])), bw = W / 30;
      buckets.forEach(function (v, i) {
        var h = v ? Math.max((v / max) * (H - 24), 2) : 1;
        ctx.fillStyle = v ? "#4C90F0" : "#1c2127";
        ctx.fillRect(i * bw + 1, H - 14 - h, Math.max(bw - 2, 1), h);
      });
      ctx.fillStyle = "#5F6B7C"; ctx.font = "10px monospace";
      ctx.fillText("peak " + max + "/10s", 4, 12);
      spark.setMeta(evs.length + " in window");

      /* triage queue */
      var q = al.filter(function (a) { return a.status === "new" && (a.severity === "critical" || a.severity === "high"); })
                .sort(function (a, b) {
                  var d = ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity);
                  return d || b.ts - a.ts;
                }).slice(0, 40);
      triage.setMeta(q.length + " awaiting action");
      triage._body.innerHTML = "";
      if (!q.length) { triage._body.appendChild(empty("no untriaged critical or high alerts — detections appear here the moment a rule fires")); }
      q.forEach(function (a) {
        var r = mk("div", "lv-row");
        r.appendChild(dot(a.severity));
        var t = mk("span", "lv-t", fmtT(a.ts)); t.style.flex = "0 0 64px"; r.appendChild(t);
        var rule = mk("span", null, a.rule); rule.style.cssText = "flex:0 0 150px;color:" + sevColor(a.severity);
        r.appendChild(rule);
        var ttl = mk("span", null, a.title); ttl.style.flex = "1"; ttl.title = a.title; r.appendChild(ttl);
        r.appendChild(respondInline(a));
        triage._body.appendChild(r);
      });

      /* sensor health */
      health._body.innerHTML = "";
      [["uptime", dur(Date.now() / 1000 - st.started)],
       ["kernel trace", st.kernel_trace ? "ETW active" : "fallback (4688 + WMI)"],
       ["eventlog records", (st.eventlog_records || 0).toLocaleString()],
       ["files scanned", (st.files_scanned || 0).toLocaleString()],
       ["signature hits", st.signatures_hit || 0]].forEach(function (kv) {
        var r = mk("div", "lv-kv");
        r.appendChild(mk("span", "k", kv[0]));
        var v = mk("span", "v", String(kv[1]));
        if (kv[0] === "kernel trace") v.style.color = st.kernel_trace ? "var(--green5)" : "var(--fg3)";
        if (kv[0] === "signature hits" && st.signatures_hit) v.style.color = sevColor("critical");
        r.appendChild(v); health._body.appendChild(r);
      });
      health._body.appendChild(mk("div", "lv-sub", "active sources"));
      var chips = mk("div", "lv-chips");
      (st.sources || []).forEach(function (src) { chips.appendChild(mk("span", "lv-chip", src)); });
      health._body.appendChild(chips);
    };
  })();

  /* ================================================================ 2 · LOG EXPLORER */
  var loadEvents = (function () {
    var body = BODY[1]; if (!body) return function () {};
    buildStrip(body);
    var f = { severity: "", source: "", kind: "", q: "" };
    var reg = region(body);
    var left = col("0 0 236px"), right = col("1");
    reg.appendChild(left); reg.appendChild(right);

    var searchP = panel("search", { grow: "0 0 auto" });
    var search = mk("input", "lv-input"); search.placeholder = "title + raw record…";
    searchP._body.appendChild(search);
    left.appendChild(searchP);
    var qT;
    search.oninput = function () {
      var v = this.value; clearTimeout(qT);
      qT = setTimeout(function () { f.q = v; load(); }, 280);
    };

    var facetPanels = {};
    ["severity", "source", "kind"].forEach(function (k) {
      var p = panel(k, { grow: "0 0 auto" });
      facetPanels[k] = p; left.appendChild(p);
    });
    var resetP = panel("filters", { grow: "0 0 auto" });
    resetP._body.appendChild(btn("Reset all filters", "", function () {
      f = { severity: "", source: "", kind: "", q: "" }; search.value = ""; load();
    }));
    left.appendChild(resetP);

    var table = panel("events", { grow: "1", pad0: true });
    right.appendChild(table);

    function facet(k) {
      var p = facetPanels[k]; p._body.innerHTML = "";
      var counts = {};
      CACHE.events.forEach(function (e) { var v = e[k]; if (v != null) counts[v] = (counts[v] || 0) + 1; });
      var keys = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; }).slice(0, 8);
      if (!keys.length) { p._body.appendChild(empty("no data")); return; }
      var max = counts[keys[0]] || 1;
      keys.forEach(function (kk) {
        var r = mk("div", "lv-facet" + (f[k] === kk ? " on" : ""));
        var nm = mk("span", "nm", kk); nm.title = kk;
        if (k === "severity") { nm.style.color = sevColor(kk); }
        var bar = mk("span", "bar"), fill = mk("i");
        fill.style.width = (counts[kk] / max * 100) + "%";
        if (k === "severity") fill.style.background = sevColor(kk);
        bar.appendChild(fill);
        r.appendChild(nm); r.appendChild(bar); r.appendChild(mk("span", "ct", counts[kk]));
        r.onclick = function () { f[k] = f[k] === kk ? "" : kk; load(); };
        p._body.appendChild(r);
      });
    }
    function drawer(e) {
      var old = $(".lv-drawer"); if (old) old.remove();
      var d = mk("div", "lv-drawer");
      var h = mk("div", "dh");
      h.appendChild(document.createTextNode(e.kind + " · " + e.severity));
      var x = mk("span", "dx", "✕"); x.onclick = function () { d.remove(); };
      h.appendChild(x);
      var pre = mk("pre"); pre.textContent = JSON.stringify(e, null, 2);
      d.appendChild(h); d.appendChild(pre);
      document.body.appendChild(d);
    }
    function render() {
      ["severity", "source", "kind"].forEach(facet);
      table.setMeta(CACHE.events.length + " shown · click a row for the raw record");
      table._body.innerHTML = "";
      if (!CACHE.events.length) { table._body.appendChild(empty("no events match — sensors warming up or filters too narrow")); return; }
      CACHE.events.slice().reverse().forEach(function (e) {
        var r = mk("div", "lv-row click");
        r.appendChild(dot(e.severity));
        var cells = [[fmtT(e.ts), "0 0 64px", "lv-t"], [e.severity, "0 0 62px", null],
                     [e.source, "0 0 92px", "lv-t"], [e.kind, "0 0 68px", "lv-t"], [e.title, "1", null]];
        cells.forEach(function (c) {
          var s = mk("span", c[2], c[0]); s.style.flex = c[1];
          if (c[0] === e.severity) s.style.color = sevColor(e.severity);
          if (c[0] === e.title) s.title = e.title;
          r.appendChild(s);
        });
        r.onclick = function () { drawer(e); };
        table._body.appendChild(r);
      });
    }
    function load() {
      var p = new URLSearchParams();
      ["severity", "source", "kind"].forEach(function (k) { if (f[k]) p.set(k, f[k]); });
      if (f.q) p.set("q", f.q);
      getJSON("/api/events?" + p).then(function (evs) { CACHE.events = evs; render(); });
    }
    return load;
  })();

  /* ================================================================ 3 · ALERTS */
  var renderAlerts = (function () {
    var body = BODY[2]; if (!body) return function () {};
    buildStrip(body);
    var reg = region(body);
    var left = col("1.5"), right = col("1");
    reg.appendChild(left); reg.appendChild(right);

    var listP = panel("alerts grouped by rule", { grow: "1", pad0: true });
    left.appendChild(listP);

    var whyP = panel("why this fired", { grow: "1 1 auto" });
    whyP._body.appendChild(empty("select an alert to see the matched selection and raw event"));
    right.appendChild(whyP);

    var cadP = panel("beacon cadence", { grow: "0 0 auto" });
    var cv = mk("canvas"); cv.style.cssText = "width:100%;height:96px;display:block;background:var(--well);border:1px solid var(--line);border-radius:2px";
    cadP._body.appendChild(cv);
    var cadNote = mk("div", "lv-mut"); cadP._body.appendChild(cadNote);
    right.appendChild(cadP);

    function showWhy(a) {
      whyP._body.innerHTML = "";
      var t = mk("div"); t.style.cssText = "font:600 13px var(--ui);color:var(--fg)";
      t.appendChild(sevBadge(a.severity));
      t.appendChild(document.createTextNode(" [" + a.rule + "] " + a.title));
      whyP._body.appendChild(t);
      if (a.why) { var w = mk("div"); w.style.cssText = "font:12px/1.5 var(--ui);color:var(--fg2)"; w.textContent = a.why; whyP._body.appendChild(w); }
      whyP._body.appendChild(mk("div", "lv-sub", "matched data"));
      var d = mk("pre"); d.style.cssText = "margin:0;font:11px var(--mono);color:#C5CBD3;white-space:pre-wrap;background:var(--well);padding:9px;border:1px solid var(--line);border-radius:2px";
      d.textContent = JSON.stringify(a.data || {}, null, 2);
      whyP._body.appendChild(d);
      if (a.event) {
        whyP._body.appendChild(mk("div", "lv-sub", "source event"));
        var r = mk("pre"); r.style.cssText = "margin:0;font:10.5px var(--mono);color:var(--fg4);white-space:pre-wrap";
        r.textContent = JSON.stringify(a.event, null, 2);
        whyP._body.appendChild(r);
      }
    }

    function statusPill(status) {
      var map = { new: ["#FFC7C9", "rgba(205,66,70,.20)"], ack: ["#FBD9B5", "rgba(236,154,60,.18)"],
                  resolved: ["#B7E6CE", "rgba(114,202,155,.16)"] };
      var m = map[status] || map.new;
      return pill(status, m[0], m[1]);
    }
    function respondBtns(a) {
      var box = mk("span", "lv-acts");
      var d = a.data || {}, ev = a.event || {};
      function add(label, color, post) {
        var b = mk("button", "lv-actbtn", label);
        b.style.color = "#fff"; b.style.background = color;
        b.onclick = function (e) {
          e.stopPropagation();
          getJSON("/api/respond", 1, post).then(function (r) {
            b.textContent = (r.ok ? "✓ " : "✗ ") + label;
            b.style.background = r.ok ? "#1C6E42" : "#8E292C";
            setTimeout(tick, 400);
          });
        };
        box.appendChild(b);
      }
      if (d.pid) add("kill " + d.pid, "#A82A2A", { action: "kill", pid: d.pid });
      if (d.peer) add("block", "#935610", { action: "block", peer: d.peer });
      var path = d.path || (ev.data && ev.data.path);
      if (path && /SIG-|IMPLANT|TEMP|WEBSHELL/.test(a.rule)) add("quarantine", "#634DBF", { action: "quarantine", path: path });
      return box;
    }

    return function (s) {
      var al = s.alerts || [];
      listP.setMeta(al.length + " total");
      listP._body.innerHTML = "";
      if (!al.length) { listP._body.appendChild(empty("no alerts — nothing detected yet")); return; }
      var groups = {};
      al.forEach(function (a) { (groups[a.rule] = groups[a.rule] || []).push(a); });
      Object.keys(groups).sort(function (x, y) {
        return ORDER.indexOf(groups[x][0].severity) - ORDER.indexOf(groups[y][0].severity);
      }).forEach(function (g) {
        var list = groups[g].slice().sort(function (a, b) { return b.ts - a.ts; });
        var a0 = list[0];
        var newN = list.filter(function (a) { return a.status === "new"; }).length;
        var wrap = mk("div"); wrap.style.borderBottom = "1px solid var(--line)";
        var head = mk("div", "lv-row click");
        head.style.background = "#20262d"; head.style.height = "30px";
        head.appendChild(dot(a0.severity));
        var rid = mk("span", null, g); rid.style.cssText = "flex:0 0 165px;color:" + sevColor(a0.severity) + ";font-weight:600";
        head.appendChild(rid);
        var nm = mk("span", null, a0.title); nm.style.flex = "1"; nm.title = a0.title; head.appendChild(nm);
        if (newN) head.appendChild(pill(newN + " new", "#FFC7C9", "rgba(205,66,70,.22)"));
        var cnt = mk("span", "lv-t", list.length + "×"); cnt.style.flex = "0 0 34px"; cnt.style.textAlign = "right";
        head.appendChild(cnt);
        wrap.appendChild(head);

        var open = false;
        var rows = mk("div"); rows.style.display = "none"; wrap.appendChild(rows);
        head.onclick = function () { open = !open; rows.style.display = open ? "" : "none"; };

        list.forEach(function (a) {
          var r = mk("div", "lv-row click");
          var t = mk("span", "lv-t", fmtT(a.ts)); t.style.flex = "0 0 64px"; r.appendChild(t);
          var ttl = mk("span", null, a.title); ttl.style.flex = "1"; ttl.title = a.title; r.appendChild(ttl);
          r.appendChild(statusPill(a.status));
          r.appendChild(respondBtns(a));
          var sb = mk("span", "lv-acts");
          [["ack", "ack", "#404854"], ["resolve", "resolved", "#404854"]].forEach(function (pb) {
            var b = mk("button", "lv-actbtn", pb[0]); b.style.color = "#F6F7F9"; b.style.background = pb[2];
            b.onclick = function (e) {
              e.stopPropagation();
              getJSON("/api/alerts/status", 1, { id: a.id, status: pb[1] }).then(tick);
            };
            sb.appendChild(b);
          });
          r.appendChild(sb);
          r.onclick = function (e) { if (e.target.tagName === "BUTTON") return; showWhy(a); };
          rows.appendChild(r);
        });
        listP._body.appendChild(wrap);
      });
    };
  })();

  var renderCadence = (function () {
    var body = BODY[2]; if (!body) return function () {};
    return function (cs) {
      var cadP = $$(".lv-panel", body).filter(function (p) { return /beacon cadence/i.test(p._label ? p._label.textContent : ""); })[0];
      if (!cadP) return;
      var cv = cadP.querySelector("canvas"), note = cadP.querySelector(".lv-mut");
      var ctx = cv.getContext("2d");
      var W = cv.width = cv.clientWidth || 420, H = cv.height = 96;
      ctx.clearRect(0, 0, W, H);
      if (!cs || !cs.length) {
        note.textContent = "no beacon flagged — needs ≥6 near-constant callbacks to one peer";
        ctx.fillStyle = "#5F6B7C"; ctx.font = "11px monospace"; ctx.fillText("no beacon data", 10, 20);
        return;
      }
      var b = cs[0], maxT = b.series[b.series.length - 1] || 1;
      ctx.strokeStyle = "#20262d"; ctx.beginPath(); ctx.moveTo(0, H - 10.5); ctx.lineTo(W, H - 10.5); ctx.stroke();
      b.series.forEach(function (t) {
        var x = t / maxT * (W - 24) + 14;
        ctx.fillStyle = "#CD4246"; ctx.fillRect(x - 1, 8, 2.5, H - 24);
      });
      note.textContent = "pid " + b.pid + " → " + b.peer + " · ~" + b.interval + "s · " + b.obs +
        " callbacks" + (cs.length > 1 ? " · " + (cs.length - 1) + " more peer(s)" : "");
    };
  })();

  /* ================================================================ 4 · SIGNATURES */
  var renderRules = (function () {
    var body = BODY[3]; if (!body) return function () {};
    buildStrip(body);
    var reg = region(body);
    var left = col("1.5"), right = col("1");
    reg.appendChild(left); reg.appendChild(right);

    var listP = panel("detection rules", { grow: "1", pad0: true });
    left.appendChild(listP);

    var testP = panel("live rule test", { grow: "0 0 auto" });
    testP._body.appendChild(mk("div", "lv-mut",
      "Paste a command line, path, or file content — evaluated against every enabled rule and signature pack."));
    var ta = mk("textarea", "lv-ta");
    ta.placeholder = "powershell -NoProfile -EncodedCommand aQBlAHgA…";
    testP._body.appendChild(ta);
    var runRow = mk("div", "lv-acts");
    var out = mk("div"); out.style.marginTop = "4px";
    runRow.appendChild(btn("Test against rules", "primary", function () {
      if (!ta.value.trim()) { out.innerHTML = ""; out.appendChild(empty("enter a sample first")); return; }
      getJSON("/api/test", 1, { text: ta.value }).then(function (r) {
        out.innerHTML = "";
        if (!r.matches.length) { out.appendChild(empty("no rule matched this sample")); return; }
        r.matches.forEach(function (m) {
          var rr = mk("div", "lv-row");
          rr.appendChild(dot(m.severity));
          var sv = mk("span", null, m.severity); sv.style.cssText = "flex:0 0 62px;color:" + sevColor(m.severity);
          rr.appendChild(sv);
          var id = mk("span", null, m.rule); id.style.flex = "0 0 160px"; rr.appendChild(id);
          var nm = mk("span", "lv-t", m.name + " (" + m.matched_field + ")"); nm.style.flex = "1"; nm.title = m.name;
          rr.appendChild(nm);
          out.appendChild(rr);
        });
      });
    }));
    testP._body.appendChild(runRow);
    testP._body.appendChild(out);
    right.appendChild(testP);

    var sigP = panel("signature packs — byte-rule hits", { grow: "0 0 auto", pad0: true });
    right.appendChild(sigP);

    return function (rl) {
      var en = rl.filter(function (r) { return r.enabled; }).length;
      listP.setMeta(en + " of " + rl.length + " enabled");
      listP._body.innerHTML = "";
      rl.slice().sort(function (a, b) {
        var d = ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity);
        return d || (b.hits || 0) - (a.hits || 0);
      }).forEach(function (r) {
        var rw = mk("div", "lv-rule");
        var sw = mk("div", "lv-sw " + (r.enabled ? "on" : "off")); sw.appendChild(mk("i"));
        sw.onclick = function () { getJSON("/api/rules/toggle", 1, { id: r.id, enabled: !r.enabled }).then(tick); };
        rw.appendChild(sw);
        var sv = mk("span", null, r.severity); sv.style.cssText = "flex:0 0 62px;color:" + sevColor(r.severity) + ";font-weight:600";
        rw.appendChild(sv);
        var id = mk("span", null, r.id); id.style.flex = "0 0 168px"; rw.appendChild(id);
        var nm = mk("span", "lv-t", r.name); nm.style.cssText = "flex:1;overflow:hidden;text-overflow:ellipsis"; nm.title = r.why || r.name;
        rw.appendChild(nm);
        var hits = mk("span", null, (r.hits || 0) + " hits");
        hits.style.cssText = "flex:0 0 66px;text-align:right;color:" + (r.hits ? "var(--blue5)" : "var(--fg4)");
        rw.appendChild(hits);
        listP._body.appendChild(rw);
      });

      sigP._body.innerHTML = "";
      var hits = (CACHE.state && CACHE.state.rule_hits) || {};
      var packs = ["SIG-REALM-IMIX", "SIG-RUST-IMPLANT", "SIG-MUSL-ELF", "SIG-ELDRITCH-TOME",
                   "SIG-WEBSHELL-PHP", "SIG-CS-BEACON", "SIG-HAVOC-DEMON"];
      var hitN = packs.filter(function (p) { return hits[p]; }).length;
      sigP.setMeta(hitN + " triggered");
      packs.forEach(function (p) {
        var on = !!hits[p];
        var r = mk("div", "lv-row");
        if (on) r.appendChild(dot("critical")); else { var s = mk("span", "lv-dot"); s.style.background = "#2f343c"; r.appendChild(s); }
        var nm = mk("span", null, p); nm.style.flex = "1"; if (on) nm.style.color = sevColor("critical");
        r.appendChild(nm);
        var h = mk("span", null, (hits[p] || 0) + " hits"); h.style.cssText = "flex:0 0 66px;text-align:right;color:" + (on ? "var(--blue5)" : "var(--fg4)");
        r.appendChild(h);
        sigP._body.appendChild(r);
      });
    };
  })();

  /* ================================================================ 5 · THREAT INTEL */
  var renderIntel = (function () {
    var body = BODY[4]; if (!body) return function () {};
    buildStrip(body);
    var reg = region(body);
    var left = col("1.2"), right = col("1");
    reg.appendChild(left); reg.appendChild(right);

    var cardsP = panel("framework indicators — live hit counts", { grow: "1" });
    left.appendChild(cardsP);
    var chainP = panel("attack chain — live event counts per stage", { grow: "1" });
    right.appendChild(chainP);

    var INTEL = [
      ["Havoc / Demon", "T1055 · T1562.001", "sleep-obfuscation agent; beacon cadence + static Demon indicators",
       ["SIG-HAVOC-DEMON", "NET-BEACON", "PROC-RUNDLL-NOARG"]],
      ["Cobalt Strike / Beacon", "T1071.001 · T1547.003", "malleable C2; service artifacts + cadence",
       ["SIG-CS-BEACON", "EVT-7045", "PERS-SERVICE", "NET-BEACON"]],
      ["Mythic (Apollo/Poseidon)", "T1059.001 · T1505.003", "webshell→stager chain; encoded PS + webshell sigs",
       ["PROC-ENC-PS", "SIG-WEBSHELL-PHP", "NET-BEACON"]],
      ["Realm / imix", "T1071 · T1543.003", "Rust implant + eldritch tomes; config-surface signatures",
       ["SIG-REALM-IMIX", "SIG-RUST-IMPLANT", "SIG-MUSL-ELF", "SIG-ELDRITCH-TOME", "EVT-4688-TEMP"]]
    ];

    return function (s) {
      var hits = s.rule_hits || {};
      cardsP._body.innerHTML = "";
      INTEL.forEach(function (f) {
        var total = f[3].reduce(function (n, r) { return n + (hits[r] || 0); }, 0);
        var c = mk("div", "lv-card");
        c.style.borderLeftColor = total ? sevColor("critical") : "#4C90F0";
        var t = mk("div", "ttl"); t.textContent = f[0];
        if (total) { var b = pill(total + " hits", "#FFC7C9", "rgba(205,66,70,.2)"); b.style.marginLeft = "8px"; t.appendChild(b); }
        c.appendChild(t);
        c.appendChild(mk("div", "sub", f[1] + " · " + f[2]));
        f[3].forEach(function (r) {
          var rw = mk("div", "lv-kv");
          rw.appendChild(mk("span", "v", r));
          var v = mk("span"); v.style.cssText = "margin-left:auto;color:" + (hits[r] ? "var(--blue5)" : "var(--fg4)"); v.textContent = hits[r] || 0;
          rw.appendChild(v); c.appendChild(rw);
        });
        cardsP._body.appendChild(c);
      });

      chainP._body.innerHTML = "";
      var evs = s.events || [];
      [["Initial access", function (e) { return e.kind === "file" && /signature|webshell/i.test(e.title); }, "T1190 / T1566"],
       ["Execution", function (e) { return e.kind === "process"; }, "T1059"],
       ["Persistence", function (e) { return ["registry", "service", "task", "wmi"].indexOf(e.kind) >= 0; }, "T1543 / T1547"],
       ["Command & control", function (e) { return e.kind === "network"; }, "T1071"],
       ["Defense evasion", function (e) { return /1102|cleared|amsi|exclusion/i.test(e.title + JSON.stringify(e.data || {})); }, "T1562 / T1070"]]
      .forEach(function (st) {
        var n = evs.filter(st[1]).length;
        var c = mk("div", "lv-card"); c.style.borderLeftColor = n ? "#4C90F0" : "#383E47";
        var row = mk("div"); row.style.cssText = "display:flex;align-items:baseline;gap:10px";
        var num = mk("span", null, n); num.style.cssText = "font:600 22px var(--mono);color:" + (n ? "var(--fg)" : "var(--fg4)");
        var lab = mk("span", "ttl", st[0]);
        row.appendChild(num); row.appendChild(lab); c.appendChild(row);
        c.appendChild(mk("div", "sub", st[2]));
        chainP._body.appendChild(c);
      });
    };
  })();

  /* ================================================================ navbar liveness */
  function updateNav(s, rl) {
    var st = s.stats;
    var en = rl.filter(function (r) { return r.enabled; }).length, tot = rl.length;
    var newAlerts = (s.alerts || []).filter(function (a) { return a.status === "new"; }).length;
    var clock = clockUTC();
    NAV.forEach(function (n) {
      if (!n) return;
      if (n.rules) n.rules.textContent = en + "/" + tot + " rules";
      if (n.clock) n.clock.textContent = clock;
      if (n.badge) {
        n.badge.textContent = newAlerts;
        n.badge.style.display = newAlerts ? "" : "none";
      }
    });
  }

  /* ================================================================ main loop */
  function tick() {
    views.slice(0, 5).forEach(function (v) { if (v._liveCleanup) v._liveCleanup(); });
    getJSON("/api/state").then(function (s) {
      CONNECTED = true;
      CACHE.state = s;
      updateStrips(s);
      renderDash(s);
      renderAlerts(s);
      renderIntel(s);
      return getJSON("/api/rules").then(function (rl) {
        CACHE.rules = rl;
        renderRules(rl);
        updateNav(s, rl);
      });
    }).catch(function () {
      CONNECTED = false;
      if (CACHE.state) updateStrips(CACHE.state);
    });
    loadEvents();
    getJSON("/api/cadence").then(function (cs) { CACHE.cadence = cs; renderCadence(cs); }).catch(function () {});
  }
  tick();
  setInterval(tick, 2500);
})();
