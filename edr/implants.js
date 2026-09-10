/* Implants screen — seventh console section: the dedicated home for entities
   the correlation engine scores as likely/confirmed implants (the "99% sure"
   tier). Lifecycle: active -> suspended / quarantined / killed -> verified
   INACTIVE after containment checks pass. Response toolkit per entity, host
   isolation, protect-mode policy, and console-wide button interactivity. */
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

  /* click animation (idempotent — beacon_triage.js normally installs it) */
  if (!$("#lv-click-style")) {
    var css0 = mk("style"); css0.id = "lv-click-style";
    css0.textContent =
      "button{transition:transform .06s ease,filter .06s ease}" +
      "button:active{transform:translateY(1px) scale(.965);filter:brightness(1.25)}" +
      ".lv-clicked{animation:lvpop .22s cubic-bezier(.2,.9,.3,1.4)}" +
      "@keyframes lvpop{0%{transform:scale(.93)}55%{transform:scale(1.05)}100%{transform:scale(1)}}";
    document.head.appendChild(css0);
    document.addEventListener("click", function (e) {
      var b = e.target.closest ? e.target.closest("button") : null;
      if (!b) return;
      b.classList.remove("lv-clicked");
      void b.offsetWidth;
      b.classList.add("lv-clicked");
      setTimeout(function () { b.classList.remove("lv-clicked"); }, 260);
    }, true);
  }

  var views = $$(".pg-screen");
  if (views.length < 5) return;

  /* ---------------- build the seventh section --------------------------- */
  var alertsView = null;
  views.forEach(function (v) {
    if (alertsView) return;
    var nav = v.querySelector(".scr");
    var capn = $(".pg-name", v);
    if (nav && nav.firstElementChild &&
        (nav.firstElementChild.textContent || "").indexOf("Alerts") >= 0 &&
        (!capn || !/Beacon Triage|Implants/i.test(capn.textContent || ""))) {
      alertsView = v;
    }
  });
  if (!alertsView) alertsView = views[2];

  var beaconSec = null;
  views.forEach(function (v) {
    var n = $(".pg-name", v);
    if (n && /Beacon Triage/i.test(n.textContent)) beaconSec = v;
  });

  var sec = alertsView.cloneNode(false);
  sec.__isImplants = true;
  var frame = $(".pg-frame", alertsView).cloneNode(false);
  var scr = $(".scr", alertsView).cloneNode(false);
  var navbar = $(".scr", alertsView).firstElementChild.cloneNode(true);

  var TABS = ["Dashboard", "Log Explorer", "Alerts", "Signatures", "Threat Intel"];
  Array.prototype.forEach.call(navbar.querySelectorAll("div"), function (el) {
    var label = (el.textContent || "").trim();
    for (var k = 0; k < TABS.length; k++) {
      if (label.indexOf(TABS[k]) === 0) { el.style.boxShadow = ""; el.style.color = ""; break; }
    }
  });

  var body = mk("div", "lv-body");
  body.setAttribute("data-live-body", "1");
  scr.appendChild(navbar);
  scr.appendChild(body);
  frame.appendChild(scr);
  sec.appendChild(frame);
  var cap = $(".pg-cap", alertsView) ? $(".pg-cap", alertsView).cloneNode(true) : mk("div", "pg-cap");
  var nm = $(".pg-name", cap); if (nm) nm.textContent = "Implants";
  var num = $(".pg-num", cap); if (num) num.textContent = "07";
  var desc = $(".pg-desc", cap);
  if (desc) desc.textContent = "Correlated implant verdicts — every signal fused into one confidence score per entity, with quarantine, tree-kill, host isolation and verified-inactive containment.";
  sec.appendChild(cap);
  alertsView.parentNode.appendChild(sec);          // seventh screen, end of sheet

  /* ---------------- one router for ALL seven screens --------------------- */
  /* views was captured before our append: [Dash, Log, Alerts, Beacons, Sig, Intel] */
  var originals = views.filter(function (v) { return v !== beaconSec; });
  var SCREENS = { dashboard: originals[0], logs: originals[1], alerts: alertsView,
                  sigs: originals[3], intel: originals[4],
                  beacons: beaconSec, implants: sec };
  var allScreens = $$(".pg-screen");

  function showView(which) {
    var target = SCREENS[which];
    allScreens.forEach(function (v) { v.classList.toggle("is-active", v === target); });
    var s = target && target.querySelector(".scr");
    if (s) s.scrollTop = 0;
    syncTabs();
  }
  function syncTabs() {
    var active = null;
    allScreens.forEach(function (v) { if (v.classList.contains("is-active")) active = v; });
    $$(".pg-screen").forEach(function (v) {
      var nav = v.querySelector(".scr") && v.querySelector(".scr").firstElementChild;
      if (!nav) return;
      Array.prototype.forEach.call(nav.children, function (el) {
        var label = (el.textContent || "").trim();
        var mine = (label === "Implants" && v === sec) ||
                   (label === "Beacon Triage" && v === beaconSec) ||
                   (SCREENS.dashboard && label.indexOf("Dashboard") === 0 && v === SCREENS.dashboard) ||
                   (label.indexOf("Log Explorer") === 0 && v === SCREENS.logs) ||
                   (label.indexOf("Alerts") === 0 && v === SCREENS.alerts) ||
                   (label.indexOf("Signatures") === 0 && v === SCREENS.sigs) ||
                   (label.indexOf("Threat Intel") === 0 && v === SCREENS.intel);
        el.style.boxShadow = (v === active && mine) ? "inset 0 -2px 0 var(--blue4)" : "";
      });
    });
  }

  function addTab(nav, label, which, active) {
    var probe = null;
    Array.prototype.forEach.call(nav.querySelectorAll("div"), function (el) {
      var t = (el.textContent || "").trim();
      if (!probe && t.indexOf("Dashboard") === 0) probe = el;
    });
    if (!probe || !probe.parentNode) return;
    if (Array.prototype.some.call(nav.children, function (el) {
      return (el.textContent || "").trim() === label; })) return;
    var tab = probe.cloneNode(false);
    tab.textContent = label;
    tab.style.paddingLeft = "15px";
    tab.style.paddingRight = "15px";
    if (active) tab.style.boxShadow = "inset 0 -2px 0 var(--blue4)";
    tab.onclick = function () { showView(which); };
    tab.onkeydown = function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); showView(which); }
    };
    probe.parentNode.insertBefore(tab, probe.nextSibling);
  }

  /* (re)bind every navbar's tabs to the single router — includes the five
     originals, the beacon screen, and ours */
  $$(".pg-screen").forEach(function (v) {
    var nav = v.querySelector(".scr") && v.querySelector(".scr").firstElementChild;
    if (!nav) return;
    addTab(nav, "Implants", "implants", v === sec);
    if (v !== beaconSec) addTab(nav, "Beacon Triage", "beacons", false);
    Array.prototype.forEach.call(nav.children, function (el) {
      var label = (el.textContent || "").trim();
      var which = null;
      if (label === "Implants") which = "implants";
      else if (label === "Beacon Triage") which = "beacons";
      else if (label.indexOf("Dashboard") === 0) which = "dashboard";
      else if (label.indexOf("Log Explorer") === 0) which = "logs";
      else if (label.indexOf("Alerts") === 0) which = "alerts";
      else if (label.indexOf("Signatures") === 0) which = "sigs";
      else if (label.indexOf("Threat Intel") === 0) which = "intel";
      if (which) {
        el.onclick = function () { showView(which); };
        el.onkeydown = function (e) {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); showView(which); }
        };
      }
    });
  });

  /* ---------------- screen content --------------------------------------- */
  var strip = mk("div", "lv-strip");
  var liveDot = mk("span", "lv-live");
  var stripTxt = mk("span");
  var protectBtn = mk("button", "lv-actbtn", "PROTECT MODE: OFF");
  protectBtn.style.cssText = "color:var(--fg2);font-size:10px;padding:3px 10px;flex:none";
  protectBtn.onclick = function () {
    var next = !CACHE.protect;
    getJSON("/api/respond", 1, { action: "protect", enabled: next }).then(function (r) {
      CACHE.protect = !!(r && r.protect_mode);
      renderProtect();
      if (CACHE.protect) setTimeout(tick, 1200);
    });
  };
  function renderProtect() {
    protectBtn.textContent = "PROTECT MODE: " + (CACHE.protect ? "ON" : "OFF");
    protectBtn.style.color = CACHE.protect ? "#FF9966" : "var(--fg2)";
    protectBtn.style.borderColor = CACHE.protect ? "#EC9A3C" : "var(--line)";
    protectBtn.title = "Detect-vs-Protect policy: when ON, entities scoring >= confirmed " +
                       "are auto-quarantined (peers firewalled, tree killed, binary vaulted).";
  }
  strip.appendChild(liveDot); strip.appendChild(stripTxt); strip.appendChild(protectBtn);
  body.appendChild(strip);

  var isoBanner = mk("div");
  isoBanner.style.cssText = "display:none;margin:6px 0;padding:8px 10px;border:1px solid #CD4246;" +
    "background:rgba(205,66,70,.14);font:11.5px var(--mono);color:#FFC7C9;border-radius:3px";
  var isoTxt = mk("span", "HOST NETWORK ISOLATION ACTIVE — all outbound blocked, loopback (this console) exempt. ");
  isoTxt.style.marginRight = "8px";
  var isoRel = mk("button", "lv-actbtn", "Release isolation");
  isoRel.style.cssText = "color:#fff;background:#8E292C;padding:2px 10px;font-size:10px";
  isoRel.onclick = function () {
    isoRel.disabled = true; isoRel.textContent = "releasing…";
    getJSON("/api/respond", 1, { action: "release" }).then(function (r) {
      isoRel.disabled = false; isoRel.textContent = r && r.ok ? "released ✓" : "failed ✗";
      setTimeout(tick, 600);
    });
  };
  isoBanner.appendChild(isoTxt); isoBanner.appendChild(isoRel);
  body.appendChild(isoBanner);

  var region = mk("div", "lv-region");
  var left = mk("div", "lv-col"); left.style.flex = "1.15";
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

  var listP = panel("implants — correlated verdicts", "score >= 60 shown");
  left.appendChild(listP);
  var evP = panel("evidence bundle");
  right.appendChild(evP);
  var actP = panel("response");
  right.appendChild(actP);
  var logP = panel("containment log", "response + verification history");
  right.appendChild(logP);

  var CACHE = { data: null, alerts: [], protect: false, selected: null };
  var LAST_VERIFY = null;   // {key, result} — survives tick re-renders

  function fmtT(ts) { return ts ? new Date(ts * 1000).toTimeString().slice(0, 8) : "--:--:--"; }

  var STATUS_STYLE = {
    "active":           ["#CD4246", "rgba(205,66,70,.16)", "ACTIVE"],
    "monitoring":       ["#3FA6DA", "rgba(63,166,218,.14)", "MONITORING"],
    "suspended":        ["#EC9A3C", "rgba(236,154,60,.14)", "SUSPENDED"],
    "quarantined":      ["#B9A24B", "rgba(185,162,75,.14)", "QUARANTINED"],
    "quarantined-verified": ["#43B97F", "rgba(67,185,127,.15)", "INACTIVE ✓ contained"],
    "killed":           ["#8E292C", "rgba(142,41,44,.14)", "KILLED"],
    "killed-verified":  ["#43B97F", "rgba(67,185,127,.15)", "INACTIVE ✓ killed"],
    "dismissed":        ["#5F6B7C", "rgba(95,107,124,.12)", "DISMISSED"]
  };
  function statusChip(status, alive) {
    var s = STATUS_STYLE[status] || STATUS_STYLE["active"];
    var el = mk("span", null, s[2]);
    el.style.cssText = "margin-left:auto;flex:none;padding:2px 8px;border-radius:10px;font-size:10px;" +
      "color:" + s[0] + ";background:" + s[1] + ";border:1px solid " + s[0] +
      (status === "active" && alive ? ";animation:lvblink 1.6s infinite" : "");
    return el;
  }
  var blink = mk("style");
  blink.textContent = "@keyframes lvblink{0%,100%{opacity:1}50%{opacity:.45}}";
  document.head.appendChild(blink);

  function scoreBar(score) {
    var wrap = mk("div");
    wrap.style.cssText = "width:78px;flex:none;height:6px;border:1px solid var(--line);border-radius:3px;overflow:hidden";
    var fill = mk("div");
    var col = score >= 85 ? "#CD4246" : score >= 60 ? "#EC9A3C" : "#B9A24B";
    fill.style.cssText = "width:" + Math.min(100, score) + "%;height:100%;background:" + col;
    wrap.appendChild(fill);
    return wrap;
  }

  function renderList() {
    listP._body.innerHTML = "";
    var imps = ((CACHE.data || {}).implants || []).filter(function (x) { return x.score >= 60; });
    if (!imps.length) {
      listP._body.appendChild(mk("div", "lv-empty",
        "no high-confidence implants — entities crossing the confirmed threshold appear here automatically"));
      return;
    }
    imps.forEach(function (b) {
      var row = mk("div");
      row.style.cssText = "display:flex;align-items:center;gap:9px;padding:7px 8px;border-bottom:1px solid #1C2127;" +
        "cursor:pointer;font:12px var(--mono)" +
        (CACHE.selected && CACHE.selected.key === b.key ? ";background:var(--raised)" : "");
      var pct = mk("b", null, b.score + "%");
      pct.style.cssText = "min-width:34px;color:" + (b.score >= 85 ? "#FF9966" : "#FBD065");
      row.appendChild(pct);
      row.appendChild(scoreBar(b.score));
      var name = mk("span", null, b.name || b.key);
      name.style.cssText = "overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:190px;color:var(--fg)";
      row.appendChild(name);
      if (b.peers && b.peers.length) {
        var pr = mk("span", null, "→ " + b.peers.slice(0, 2).join(", "));
        pr.style.cssText = "color:var(--fg4);font-size:11px";
        row.appendChild(pr);
      }
      row.appendChild(statusChip(b.status, b.alive));
      row.onclick = function () { CACHE.selected = b; renderList(); renderEvidence(); renderActions(); };
      listP._body.appendChild(row);
    });
  }

  function renderEvidence() {
    evP._body.innerHTML = "";
    var b = CACHE.selected;
    if (!b) { evP._body.appendChild(mk("div", "lv-empty", "select an implant")); return; }
    var head = mk("div");
    head.style.cssText = "display:flex;align-items:baseline;gap:8px;margin-bottom:6px";
    var big = mk("b", null, b.score + "%");
    big.style.cssText = "font-size:22px;color:" + (b.score >= 85 ? "#FF9966" : "#FBD065");
    var tier = mk("span", null, (b.tier || "").toUpperCase() + " IMPLANT");
    tier.style.cssText = "color:var(--fg3);font-size:11px;letter-spacing:.5px";
    var st = statusChip(b.status, b.alive); st.style.marginLeft = "auto";
    head.appendChild(big); head.appendChild(tier); head.appendChild(st);
    evP._body.appendChild(head);

    var pre = mk("pre");
    pre.style.cssText = "margin:0 0 6px;font:11px var(--mono);color:#cdd2d8;white-space:pre-wrap;" +
      "background:var(--well);padding:9px;border:1px solid var(--line);border-radius:2px";
    var lines = ["entity   " + (b.name || b.key),
                 "binary   " + (b.path || "n/a (fileless / unknown image)"),
                 "pids     " + (b.pids && b.pids.length ? b.pids.join(", ") : "none seen") +
                 (b.alive ? "  [ALIVE]" : ""),
                 "c2 peers " + (b.peers && b.peers.length ? b.peers.join(", ") : "none recorded"),
                 "window   " + fmtT(b.first) + " → " + fmtT(b.last) +
                 "   status " + b.status + (b.status_by === "protect-mode" ? " (auto)" : "")];
    pre.textContent = lines.join("\n");
    evP._body.appendChild(pre);

    var tbl = mk("div");
    (b.evidence || []).slice(0, 10).forEach(function (e) {
      var r = mk("div");
      r.style.cssText = "display:flex;gap:8px;padding:3px 4px;border-bottom:1px solid #1C2127;font:11px var(--mono)";
      var w = mk("b", null, "+" + e.weight);
      w.style.cssText = "min-width:34px;color:" + (e.weight >= 30 ? "#FF9966" : "#FBD065");
      var rl = mk("span", null, e.rule + (e.count > 1 ? " ×" + e.count : ""));
      rl.style.cssText = "min-width:150px;color:#8ABBFF";
      var t = mk("span", null, e.title);
      t.style.cssText = "color:var(--fg2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
      r.appendChild(w); r.appendChild(rl); r.appendChild(t);
      tbl.appendChild(r);
    });
    evP._body.appendChild(tbl);

    /* on-demand memory scan: the awake-vs-asleep sleep-encryption exercise */
    if (b.pids && b.pids.length) {
      var scanRow = mk("div");
      scanRow.style.cssText = "display:flex;gap:6px;margin-top:6px;align-items:flex-start";
      var sb = mk("button", "lv-actbtn", "Scan memory now");
      sb.style.cssText = "flex:none;color:#0e1116;background:#8ABBFF;font-weight:bold";
      sb.onclick = function () {
        sb.disabled = true; sb.textContent = "scanning…";
        var pid = b.pids[b.pids.length - 1];
        getJSON("/api/scan/mem?pid=" + pid).then(function (r) {
          sb.disabled = false; sb.textContent = "Scan memory now";
          LAST_SCAN = { key: b.key, result: r };
          renderScan();
        }).catch(function () { sb.disabled = false; sb.textContent = "✗ scan failed"; });
      };
      scanRow.appendChild(sb);
      var scanBox = mk("div");
      scanBox.style.cssText = "flex:1;font:11px var(--mono)";
      scanBox.id = "lv-scan-box";
      scanRow.appendChild(scanBox);
      evP._body.appendChild(scanRow);
      renderScan();
    }
  }

  var LAST_SCAN = null;
  function renderScan() {
    var box = $("#lv-scan-box");
    if (!box) return;
    box.innerHTML = "";
    var b = CACHE.selected;
    if (!b || !LAST_SCAN || LAST_SCAN.key !== b.key) return;
    var r = LAST_SCAN.result || {};
    if (r.error) {
      box.appendChild(mk("div", null, "✗ " + r.error));
      return;
    }
    var head = mk("div");
    head.style.color = (r.hits && r.hits.length) ? "#FF9966" : "#43B97F";
    head.textContent = r.hits && r.hits.length
      ? "✓ SIGNATURES IN PLAINTEXT: " + r.hits.map(function (h) { return h.sig; }).join(", ")
      : "✓ " + (r.result || "clean");
    box.appendChild(head);
    (r.hits || []).forEach(function (h) {
      var d = mk("div", null, "   " + h.sig + " @ " + h.address);
      d.style.color = "var(--fg2)";
      box.appendChild(d);
    });
  }

  function actBtn(label, color, post, onDone) {
    var b = mk("button", "lv-actbtn", label);
    b.style.cssText = "color:#fff;background:" + color + ";justify-content:flex-start";
    b.onclick = function () {
      b.disabled = true;
      b.textContent = "working…";
      getJSON("/api/respond", 1, post).then(function (r) {
        b.disabled = false;
        var msg = r && r.message;
        if (msg && typeof msg === "object") {
          msg = "peers blocked: " + (msg.blocked_peers || []).join(", ") +
                " · killed: " + (msg.killed !== null && msg.killed !== undefined ? msg.killed : "n/a") +
                " · vault: " + (msg.vault ? "yes" : "no");
        }
        b.textContent = (r && r.ok ? "✓ " : "✗ ") + label + (msg ? " — " + String(msg).slice(0, 80) : "");
        b.style.background = r && r.ok ? "#1C6E42" : "#8E292C";
        if (onDone) onDone(r);
        setTimeout(function () { b.textContent = label; b.style.background = color; }, 5000);
      }).catch(function () { b.disabled = false; b.textContent = "✗ " + label; });
    };
    return b;
  }

  function renderActions() {
    actP._body.innerHTML = "";
    var b = CACHE.selected;
    if (!b) { actP._body.appendChild(mk("div", "lv-empty", "select an implant to respond")); return; }
    var pid = b.pids && b.pids.length ? b.pids[b.pids.length - 1] : null;

    var note = mk("div", "lv-mut",
      "Quarantine is full entity containment: C2 peers firewalled, process tree " +
      "terminated, binary vaulted with execute denied. The implant shows INACTIVE " +
      "once verification confirms it is dead, vaulted and silent.");
    actP._body.appendChild(note);

    var g1 = mk("div"); g1.style.cssText = "display:flex;flex-direction:column;gap:6px";
    g1.appendChild(actBtn(" Quarantine implant — cut C2 + kill tree + vault binary",
                          "#A82A2A",
                          { action: "quarantine_entity", pid: pid, peers: b.peers, path: b.path },
                          function () { setTimeout(tick, 800); setTimeout(tick, 3000); }));
    g1.appendChild(actBtn("Kill process tree — terminate whole sequence", "#8E292C",
                          { action: "kill_tree", pid: pid }));
    g1.appendChild(actBtn("Suspend — freeze, preserve memory evidence", "#935610",
                          { action: "suspend", pid: pid },
                          function () { setTimeout(tick, 600); }));
    g1.appendChild(actBtn("Block C2 egress — firewall peers, keep process", "#935610",
                          { action: "block", peer: b.peers && b.peers[0] }));
    actP._body.appendChild(g1);

    var g2 = mk("div"); g2.style.cssText = "display:flex;gap:6px;margin-top:6px";
    var ver = mk("button", "lv-actbtn", "Verify containment");
    ver.style.cssText = "flex:1.4;color:#0e1116;background:#43B97F;font-weight:bold";
    ver.onclick = function () {
      ver.disabled = true; ver.textContent = "checking…";
      getJSON("/api/implants/verify", 1, { key: b.key }).then(function (r) {
        ver.disabled = false; ver.textContent = "Verify containment";
        LAST_VERIFY = { key: b.key, result: r };
        renderVerify(r);
        setTimeout(tick, 400);
      });
    };
    var mon = mk("button", "lv-actbtn", "Monitor");
    mon.style.cssText = "flex:1;color:var(--fg2)";
    mon.onclick = function () {
      getJSON("/api/respond", 1, { action: "entity_status", key: b.key, status: "monitoring" })
        .then(function () { setTimeout(tick, 400); });
    };
    var dis = mk("button", "lv-actbtn", "Dismiss");
    dis.style.cssText = "flex:1;color:var(--fg2)";
    dis.onclick = function () {
      getJSON("/api/respond", 1, { action: "entity_status", key: b.key, status: "dismissed" })
        .then(function () { setTimeout(tick, 400); });
    };
    g2.appendChild(ver); g2.appendChild(mon); g2.appendChild(dis);
    actP._body.appendChild(g2);

    /* verification result area */
    var verBox = mk("div");
    verBox.style.cssText = "margin-top:8px";
    verBox.id = "lv-verify-box";
    actP._body.appendChild(verBox);

    var host = mk("div");
    host.style.cssText = "margin-top:10px;padding-top:8px;border-top:1px solid var(--line)";
    var ht = mk("div", "lv-mut",
      "Host-level (Defender-style device isolation): blocks ALL outbound — no C2 " +
      "channel survives. Loopback is exempt so this console stays reachable.");
    ht.style.marginBottom = "6px";
    var hg = mk("div"); hg.style.cssText = "display:flex;gap:6px";
    var iso = actBtn("Isolate host — cut all egress", "#A82A2A", { action: "isolate" },
                     function () { setTimeout(tick, 500); });
    iso.style.flex = "1";
    var rel = actBtn("Release isolation", "#2D5D9B", { action: "release" },
                     function () { setTimeout(tick, 500); });
    rel.style.flex = "1";
    hg.appendChild(iso); hg.appendChild(rel);
    host.appendChild(ht); host.appendChild(hg);
    actP._body.appendChild(host);
  }

  function renderVerify(r) {
    var box = $("#lv-verify-box");
    if (!box || !r) return;
    box.innerHTML = "";
    var head = mk("div");
    head.style.cssText = "font:11.5px var(--mono);font-weight:bold;color:" +
      (r.all_pass ? "#43B97F" : "#EC9A3C");
    head.textContent = (r.all_pass ? "✓ CONTAINED — verified inactive" :
                        "containment not yet verified:") + "  (status: " + r.status + ")";
    box.appendChild(head);
    (r.checks || []).forEach(function (c) {
      var row = mk("div");
      row.style.cssText = "display:flex;gap:8px;padding:2px 2px;font:11px var(--mono);color:var(--fg2)";
      var mark = mk("span", null, c.pass ? "✓" : "✗");
      mark.style.color = c.pass ? "#43B97F" : "#CD4246";
      mark.style.minWidth = "14px";
      var n = mk("span", null, c.name);
      n.style.minWidth = "150px"; n.style.color = "var(--fg)";
      var d = mk("span", null, c.detail);
      d.style.overflow = "hidden"; d.style.textOverflow = "ellipsis";
      row.appendChild(mark); row.appendChild(n); row.appendChild(d);
      box.appendChild(row);
    });
  }

  function renderLog() {
    logP._body.innerHTML = "";
    var acts = (CACHE.alerts || []).filter(function (a) {
      return a.rule && (a.rule.indexOf("RESP-") === 0);
    }).sort(function (x, y) { return y.ts - x.ts; }).slice(0, 14);
    if (!acts.length) { logP._body.appendChild(mk("div", "lv-empty", "no response actions yet")); return; }
    acts.forEach(function (a) {
      var row = mk("div");
      row.style.cssText = "display:flex;gap:10px;padding:4px 6px;border-bottom:1px solid #1C2127;font:11.5px var(--mono)";
      var t = mk("span", null, fmtT(a.ts)); t.style.color = "var(--fg4)"; t.style.minWidth = "58px";
      var rl = mk("b", null, a.rule.replace("RESP-", "")); rl.style.minWidth = "96px";
      rl.style.color = /KILL|ISOLATE|QUARANTINE/.test(a.rule) ? "#FF9966" : "#8ABBFF";
      var d = mk("span", null, (a.title || "").replace(/^Response: /, ""));
      d.style.color = "var(--fg2)"; d.style.overflow = "hidden"; d.style.textOverflow = "ellipsis";
      row.appendChild(t); row.appendChild(rl); row.appendChild(d);
      logP._body.appendChild(row);
    });
  }

  function tick() {
    getJSON("/api/implants").then(function (d) {
      CACHE.data = d;
      CACHE.protect = !!d.protect_mode;
      renderProtect();
      var imps = d.implants || [];
      var contained = imps.filter(function (x) {
        return /quarantined|killed|suspended/.test(x.status); }).length;
      stripTxt.innerHTML = "";
      stripTxt.appendChild(mk("b", null, String(imps.length)));
      stripTxt.appendChild(document.createTextNode(" entities scored · " +
        imps.filter(function (x) { return x.tier === "confirmed"; }).length + " confirmed · " +
        contained + " contained"));
      if (CACHE.selected) {
        var again = imps.filter(function (x) { return x.key === CACHE.selected.key; })[0];
        if (again) CACHE.selected = again; else CACHE.selected = null;
      }
      renderList(); renderEvidence(); renderActions();
    }).catch(function () { liveDot.classList.add("off"); });
    getJSON("/api/state").then(function (s) {
      CACHE.alerts = s.alerts || [];
      var iso = false;
      (CACHE.alerts || []).forEach(function (a) {
        if (a.rule === "RESP-ISOLATE") iso = !(a.data || {}).released;
      });
      isoBanner.style.display = iso ? "block" : "none";
      renderLog();
    });
  }
  tick();
  setInterval(tick, 3000);

  /* hash deep-link */
  function applyHash() {
    var h = (location.hash || "").replace(/^#/, "").toLowerCase();
    if (h === "implants") showView("implants");
    else if (h === "beacons" && beaconSec) showView("beacons");
  }
  window.addEventListener("hashchange", applyHash);
  applyHash();

  /* keep the selected implant's verify box when re-rendered */
  var _renderActions = renderActions;
  renderActions = function () {
    _renderActions();
    var b = CACHE.selected;
    if (b && LAST_VERIFY && LAST_VERIFY.key === b.key)
      renderVerify(LAST_VERIFY.result);
  };

  /* ---------------- console-wide button interactivity sweep -------------- */
  /* every rendered button must react to a click: functional ones already have
     handlers; anything left dead gets a visible acknowledgement so no control
     in the console is inert */
  var toast = mk("div");
  toast.style.cssText = "position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(8px);" +
    "background:var(--raised,#22262c);color:var(--fg,#edeff2);border:1px solid var(--line,#2a2f37);" +
    "padding:7px 14px;font:11.5px var(--mono);border-radius:4px;opacity:0;pointer-events:none;" +
    "transition:opacity .18s ease,transform .18s ease;z-index:99999";
  document.body.appendChild(toast);
  var toastTimer = null;
  function say(msg) {
    toast.textContent = msg;
    toast.style.opacity = "1";
    toast.style.transform = "translateX(-50%) translateY(0)";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(-50%) translateY(8px)";
    }, 1600);
  }

  function sweepDeadButtons() {
    $$("button").forEach(function (b) {
      if (b.__lvWired) return;
      var has = b.onclick || b.getAttribute("onclick") ||
                (typeof b.addEventListener === "function" && b.getEventListeners);
      /* jQuery-style bound handlers are invisible here; only claim buttons
         with no inline/jsdom handler we can see AND no disabled state */
      if (has || b.disabled) return;
      b.__lvWired = true;
      b.addEventListener("click", function () {
        say("• " + ((b.textContent || "control").trim().slice(0, 40) || "control") +
            " — bound (no remote action)");
      });
    });
  }
  setInterval(sweepDeadButtons, 4000);
  sweepDeadButtons();

  /* export the refresh hook so other screens can trigger a global re-fetch */
  window.__edrRefreshHooks = window.__edrRefreshHooks || [];
  window.__edrRefreshHooks.push(tick);
})();
