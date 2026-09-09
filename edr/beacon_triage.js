/* Beacon Triage screen — a sixth console section in the same design idiom.
   Lists every detected beacon (cadence alerts + live cadence series) and
   gives per-beacon containment decisions: suspend (freeze, keep evidence),
   block egress (firewall, keep process), kill, monitor-only, resolve.
   Also installs the global button click animation. */
(function () {
  "use strict";
  function $(s, r) { return (r || document).querySelector(s); }
  function $$(s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); }
  function mk(t, cls, txt) {
    var e = document.createElement(t);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = txt;
    return e;
  }
  function getJSON(url, post, body) {
    return fetch(url, post ? { method: "POST", headers: { "Content-Type": "application/json" },
                               body: JSON.stringify(body || {}) } : undefined)
      .then(function (r) { return r.json(); });
  }

  /* ---------------- click animation (all buttons, everywhere) ------------ */
  if (!$("#lv-click-style")) {
    var css = mk("style"); css.id = "lv-click-style";
    css.textContent =
      "button{transition:transform .06s ease,filter .06s ease}" +
      "button:active{transform:translateY(1px) scale(.965);filter:brightness(1.25)}" +
      ".lv-clicked{animation:lvpop .22s cubic-bezier(.2,.9,.3,1.4)}" +
      "@keyframes lvpop{0%{transform:scale(.93)}55%{transform:scale(1.05)}100%{transform:scale(1)}}";
    document.head.appendChild(css);
    document.addEventListener("click", function (e) {
      var b = e.target.closest ? e.target.closest("button") : null;
      if (!b) return;
      b.classList.remove("lv-clicked");
      void b.offsetWidth;                    // restart the animation
      b.classList.add("lv-clicked");
      setTimeout(function () { b.classList.remove("lv-clicked"); }, 260);
    }, true);
  }

  var views = $$(".pg-screen");
  if (views.length < 5) return;

  /* ---------------- build the sixth section ------------------------------ */
  var alertsView = views[2];
  var sec = alertsView.cloneNode(false);          // same classes (pg-screen)
  var frame = $(".pg-frame", alertsView).cloneNode(false);
  var scr = $(".scr", alertsView).cloneNode(false);
  var navbar = $(".scr", alertsView).firstElementChild.cloneNode(true);

  /* relabel the clone's tabs: our tab active, others normal */
  var TABS = ["Dashboard", "Log Explorer", "Alerts", "Signatures", "Threat Intel"];
  var navTabs = [];
  Array.prototype.forEach.call(navbar.querySelectorAll("div"), function (el) {
    var label = (el.textContent || "").trim();
    for (var k = 0; k < TABS.length; k++) {
      if (label.indexOf(TABS[k]) === 0) { navTabs.push({ el: el, idx: k }); break; }
    }
  });
  navTabs.forEach(function (t) {
    t.el.style.boxShadow = "";
    t.el.style.color = "";
  });

  var body = mk("div", "lv-body");
  body.setAttribute("data-live-body", "1");
  scr.appendChild(navbar);
  scr.appendChild(body);
  frame.appendChild(scr);
  sec.appendChild(frame);                         // the screen itself
  var cap = $(".pg-cap", alertsView) ? $(".pg-cap", alertsView).cloneNode(true) : mk("div", "pg-cap");
  var nm = $(".pg-name", cap); if (nm) nm.textContent = "Beacon Triage";
  var num = $(".pg-num", cap); if (num) num.textContent = "06";
  var desc = $(".pg-desc", cap);
  if (desc) desc.textContent = "Per-beacon containment decisions: suspend (freeze, preserve evidence), block egress, or kill - with the cadence evidence beside the controls.";
  sec.appendChild(cap);
  alertsView.parentNode.insertBefore(sec, alertsView.nextSibling);

  var allViews = $$(".pg-screen");

  function showView(idx) {
    allViews.forEach(function (v, k) { v.classList.toggle("is-active", v === (idx === "beacons" ? sec : views[idx])); });
    var target = idx === "beacons" ? sec : views[idx];
    var s = target && target.querySelector(".scr");
    if (s) s.scrollTop = 0;
  }

  /* tab plumbing: add "Beacon Triage" to every navbar (ours + the five) */
  function addTriageTab(nav, active) {
    var probe = null;
    Array.prototype.forEach.call(nav.querySelectorAll("div"), function (el) {
      var t = (el.textContent || "").trim();
      if (!probe && t.indexOf("Dashboard") === 0) probe = el;
    });
    if (!probe || !probe.parentNode) return;
    var tab = probe.cloneNode(false);
    tab.textContent = "Beacon Triage";
    tab.style.paddingLeft = "15px";
    tab.style.paddingRight = "15px";
    if (active) tab.style.boxShadow = "inset 0 -2px 0 var(--blue4)";
    tab.onclick = function () { showView("beacons"); syncTabs(); };
    probe.parentNode.insertBefore(tab, probe.nextSibling);
  }
  function syncTabs() {
    var onBeacons = sec.classList.contains("is-active");
    $$("div", document).forEach(function () {});   // noop keep linter calm
    $$(".pg-screen").forEach(function (v) {
      var nav = v.querySelector(".scr") && v.querySelector(".scr").firstElementChild;
      if (!nav) return;
      Array.prototype.forEach.call(nav.children, function (el) {
        if ((el.textContent || "").trim() === "Beacon Triage") {
          el.style.boxShadow = v === sec && onBeacons ? "inset 0 -2px 0 var(--blue4)" : "";
        }
      });
    });
  }
  views.slice(0, 5).forEach(function (v) {
    var nav = v.querySelector(".scr") && v.querySelector(".scr").firstElementChild;
    if (nav) addTriageTab(nav, false);
  });
  addTriageTab(navbar, true);
  navTabs.forEach(function (t) {
    t.el.onclick = function () { showView(t.idx); syncTabs(); };
    t.el.onkeydown = function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); showView(t.idx); syncTabs(); }
    };
  });

  /* ---------------- screen content --------------------------------------- */
  var strip = mk("div", "lv-strip");
  var liveDot = mk("span", "lv-live");
  var stripTxt = mk("span");
  strip.appendChild(liveDot); strip.appendChild(stripTxt);
  body.appendChild(strip);

  var region = mk("div", "lv-region");
  var left = mk("div", "lv-col"); left.style.flex = "1.1";
  var right = mk("div", "lv-col"); right.style.flex = "1";
  region.appendChild(left); region.appendChild(right);
  body.appendChild(region);

  function panel(label, meta) {
    var p = mk("div", "lv-panel");
    var h = mk("div", "lv-phead");
    h.appendChild(mk("span", null, label));
    if (meta) h.appendChild(mk("span", "lv-meta", meta));
    p.appendChild(h);
    var b = mk("div", "lv-pbody");
    p.appendChild(b);
    p._body = b;
    return p;
  }

  var listP = panel("beacons — select one to triage");
  left.appendChild(listP);
  var evP = panel("cadence evidence");
  right.appendChild(evP);
  var actP = panel("containment decision");
  right.appendChild(actP);
  var logP = panel("decision log", "response history");
  right.appendChild(logP);

  var CACHE = { alerts: [], cadence: [], state: null };
  var selected = null;     // {pid, peer, alert}

  function fmtT(ts) { return new Date(ts * 1000).toTimeString().slice(0, 8); }
  function sevColor(s) { return { critical: "#CD4246", high: "#EC9A3C", medium: "#FBD065",
                                  low: "#3FA6DA", info: "#5F6B7C" }[s] || "#5F6B7C"; }

  function beaconRows() {
    var rows = [];
    (CACHE.alerts || []).forEach(function (a) {
      if (a.rule !== "NET-BEACON" && a.rule !== "DNS-BEACON" && a.rule !== "ICMP-BEACON") return;
      var d = a.data || {};
      rows.push({ key: a.rule + "|" + d.peer + "|" + d.pid, rule: a.rule, pid: d.pid,
                  peer: d.peer, interval: d.interval, ts: a.ts, id: a.id,
                  intel: d.intel || null, alert: a });
    });
    (CACHE.cadence || []).forEach(function (c) {
      var key = "live|NET-BEACON|" + c.peer + "|" + c.pid;
      if (!rows.some(function (r) { return r.key === key; }))
        rows.push({ key: key, rule: "NET-BEACON", pid: c.pid, peer: c.peer,
                    interval: c.interval, ts: 0, id: null, intel: null, alert: null });
    });
    var seen = {};
    return rows.filter(function (r) { return seen[r.key] ? false : (seen[r.key] = true); });
  }

  function renderList() {
    listP._body.innerHTML = "";
    var rows = beaconRows();
    if (!rows.length) {
      listP._body.appendChild(mk("div", "lv-empty",
        "no beacons detected - cadence analysis flags periodic callbacks here automatically"));
      return;
    }
    rows.forEach(function (r) {
      var sel = selected && selected.key === r.key;
      var row = mk("div", "lv-row click");
      if (sel) { row.style.background = "rgba(78,166,209,.12)"; row.style.boxShadow = "inset 2px 0 0 var(--blue4)"; }
      var dot = mk("span", "lv-dot");
      dot.style.background = sevColor(r.rule === "NET-BEACON" ? "critical" : "high");
      var peer = mk("span", null, String(r.peer));
      peer.style.cssText = "flex:0 0 140px;color:var(--fg);font-weight:600";
      var iv = mk("span", null, "~" + r.interval + "s");
      iv.style.cssText = "flex:0 0 56px;color:#EC9A3C";
      var pid = mk("span", "lv-t", "pid " + r.pid);
      pid.style.cssText = "flex:0 0 76px";
      var tag = mk("span", "lv-pill", r.rule.replace("-BEACON", ""));
      tag.style.cssText = "margin-left:auto;color:var(--fg2);background:var(--well);box-shadow:inset 0 0 0 1px var(--line)";
      row.appendChild(dot); row.appendChild(peer); row.appendChild(iv);
      row.appendChild(pid); row.appendChild(tag);
      row.onclick = function () { selected = r; renderList(); renderEvidence(); renderActions(); };
      listP._body.appendChild(row);
    });
  }

  function renderEvidence() {
    evP._body.innerHTML = "";
    if (!selected) { evP._body.appendChild(mk("div", "lv-empty", "select a beacon")); return; }
    var c = (CACHE.cadence || []).filter(function (x) { return String(x.peer) === String(selected.peer); })[0];
    var pre = mk("pre");
    pre.style.cssText = "margin:0;font:11px var(--mono);color:#cdd2d8;white-space:pre-wrap;" +
      "background:var(--well);padding:9px;border:1px solid var(--line);border-radius:2px";
    var lines = ["beacon   " + selected.peer,
                 "process  pid " + selected.pid,
                 "interval ~" + selected.interval + "s (jitter-tolerant cadence match)"];
    if (c) lines.push("samples  " + c.obs + " callbacks, gaps " + JSON.stringify(c.gaps && c.gaps.slice(0, 8)));
    if (selected.ts) lines.push("alerted  " + fmtT(selected.ts) + " (" + selected.rule + ")");
    if (selected.intel) {
      var i = selected.intel;
      lines.push("intel    " + [i["class"], i.rdns, i.asn, i.asn_holder, i.country]
        .filter(Boolean).join(" | "));
    }
    pre.textContent = lines.join("\n");
    evP._body.appendChild(pre);
    if (selected.intel && selected.alert) {
      // intel already attached to the alert - also rendered in the panel
    } else if (selected.peer && /^\d+\.\d+\.\d+\.\d+$/.test(String(selected.peer))) {
      var ib = mk("button", "lv-actbtn", "enrich IP (OSINT)");
      ib.style.cssText = "align-self:flex-start;color:#fff;background:#2D5D9B";
      ib.onclick = function () {
        ib.textContent = "loading…";
        getJSON("/api/intel?ip=" + encodeURIComponent(selected.peer)).then(function (inf) {
          selected.intel = inf;
          renderEvidence();
        });
      };
      evP._body.appendChild(ib);
    }
  }

  function actBtn(label, color, post, onDone) {
    var b = mk("button", "lv-actbtn", label);
    b.style.cssText = "color:#fff;background:" + color + ";justify-content:flex-start";
    b.onclick = function () {
      b.disabled = true;
      b.textContent = "working…";
      getJSON("/api/respond", 1, post).then(function (r) {
        b.disabled = false;
        b.textContent = (r.ok ? "✓ " : "✗ ") + label + (r.message ? " — " + String(r.message).slice(0, 60) : "");
        b.style.background = r.ok ? "#1C6E42" : "#8E292C";
        if (onDone) onDone(r);
        setTimeout(function () { b.textContent = label; b.style.background = color; }, 4000);
      }).catch(function () { b.disabled = false; b.textContent = "✗ " + label; });
    };
    return b;
  }

  function renderActions() {
    actP._body.innerHTML = "";
    if (!selected) { actP._body.appendChild(mk("div", "lv-empty", "select a beacon to decide")); return; }
    var pid = selected.pid, peer = selected.peer;

    var head = mk("div");
    head.style.cssText = "display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;font:11.5px var(--mono)";
    var kp = mk("span", "lv-t", "target"); var kv = mk("b", null, String(peer)); kv.style.color = "var(--fg)";
    var pp = mk("span", "lv-t", "· pid"); var pv = mk("span", null, String(pid)); pv.style.color = "var(--fg2)";
    head.appendChild(kp); head.appendChild(kv); head.appendChild(pp); head.appendChild(pv);
    actP._body.appendChild(head);

    function grp(t) { return mk("div", "lv-sub", t); }
    function stack() { var d = mk("div"); d.style.cssText = "display:flex;flex-direction:column;gap:6px"; return d; }
    function roww() { var d = mk("div"); d.style.cssText = "display:flex;gap:6px"; return d; }

    actP._body.appendChild(grp("contain — reversible, preserves memory for forensics"));
    var s1 = stack();
    s1.appendChild(actBtn("Suspend process  ·  recommended first move", "#34709f", { action: "suspend", pid: pid }));
    s1.appendChild(actBtn("Block egress  ·  firewall peer, keep process", "#935610", { action: "block", peer: peer }));
    actP._body.appendChild(s1);

    actP._body.appendChild(grp("release"));
    var rel = roww();
    var rb1 = actBtn("Resume process", "#2a2e33", { action: "resume", pid: pid }); rb1.style.flex = "1"; rb1.style.color = "var(--fg2)";
    var rb2 = actBtn("Unblock peer", "#2a2e33", { action: "unblock", peer: peer }); rb2.style.flex = "1"; rb2.style.color = "var(--fg2)";
    rel.appendChild(rb1); rel.appendChild(rb2);
    actP._body.appendChild(rel);

    actP._body.appendChild(grp("eradicate — destructive · guardrails refuse system-critical targets"));
    actP._body.appendChild(actBtn("Kill process", "#A82A2A", { action: "kill", pid: pid }));

    actP._body.appendChild(grp("triage"));
    var g2 = roww();
    var mon = mk("button", "lv-actbtn", "Monitor only (ack)");
    mon.style.cssText = "flex:1;color:var(--fg2);background:#2a2e33";
    mon.onclick = function () {
      if (selected.id) getJSON("/api/alerts/status", 1, { id: selected.id, status: "ack" }).then(tick);
    };
    var res = mk("button", "lv-actbtn", "Resolve");
    res.style.cssText = "flex:1;color:var(--fg2);background:#2a2e33";
    res.onclick = function () {
      if (selected.id) getJSON("/api/alerts/status", 1, { id: selected.id, status: "resolved" }).then(tick);
    };
    g2.appendChild(mon); g2.appendChild(res);
    actP._body.appendChild(g2);
  }

  function renderLog() {
    logP._body.innerHTML = "";
    var acts = (CACHE.alerts || []).filter(function (a) {
      return a.rule && a.rule.indexOf("RESP-") === 0;
    }).sort(function (x, y) { return y.ts - x.ts; }).slice(0, 12);
    if (!acts.length) { logP._body.appendChild(mk("div", "lv-empty", "no response actions yet")); return; }
    acts.forEach(function (a) {
      var row = mk("div");
      row.style.cssText = "display:flex;gap:10px;padding:4px 6px;border-bottom:1px solid #1C2127;font:11.5px var(--mono)";
      var t = mk("span", null, fmtT(a.ts)); t.style.color = "var(--fg4)"; t.style.minWidth = "58px";
      var rl = mk("b", null, a.rule.replace("RESP-", "")); rl.style.minWidth = "86px";
      rl.style.color = a.rule === "RESP-KILL" ? "#FF9966" : "#8ABBFF";
      var d = mk("span", null, (a.title || "").replace(/^Response: /, ""));
      d.style.color = "var(--fg2)"; d.style.overflow = "hidden"; d.style.textOverflow = "ellipsis";
      row.appendChild(t); row.appendChild(rl); row.appendChild(d);
      logP._body.appendChild(row);
    });
  }

  function tick() {
    getJSON("/api/state").then(function (s) {
      CACHE.alerts = s.alerts || []; CACHE.state = s;
      stripTxt.innerHTML = "";
      stripTxt.appendChild(mk("b", null, String((s.stats || {}).beacons || 0)));
      stripTxt.appendChild(document.createTextNode(" beacons flagged · " +
        ((CACHE.alerts.filter(function (a) { return a.rule === "NET-BEACON"; }).length) || 0) +
        " triage entries"));
      renderList(); renderEvidence(); renderActions(); renderLog();
    }).catch(function () { liveDot.classList.add("off"); });
    getJSON("/api/cadence").then(function (c) { CACHE.cadence = c || []; renderList(); });
  }
  tick();
  setInterval(tick, 2500);

  /* hash deep-link */
  function applyHash() {
    if ((location.hash || "").replace(/^#/, "").toLowerCase() === "beacons") {
      showView("beacons"); syncTabs();
    }
  }
  window.addEventListener("hashchange", applyHash);
  applyHash();
})();
