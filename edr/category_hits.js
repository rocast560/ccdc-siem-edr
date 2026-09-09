/* Category hit detail — "which detections are being hit, live".
   Augments the Threat Intel screen with two owned panels (per-C2-framework
   and per-attack-stage detection hits, drillable to the actual alerts), the
   Signatures screen with a live alert feed, and the Dashboard with a
   top-detections panel. Panels below the console_live ones; no interference
   with its re-render cycle. */
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
  function getJSON(url) { return fetch(url).then(function (r) { return r.json(); }); }

  /* ---------------- category -> detection rules mapping ------------------ */
  var FRAMEWORKS = {
    "Havoc / Demon": ["SIG-HAVOC-DEMON", "NET-BEACON", "PROC-RUNDLL-NOARG",
      "THREAD-HIJACK", "THREAD-UNBACKED", "STACK-UNBACKED", "MEM-RWX-UNBACKED",
      "SYSCALL-STUB", "MEM-PROMOTE", "NTDLL-TAMPER"],
    "Cobalt Strike": ["SIG-CS-BEACON", "EVT-7045", "PERS-SERVICE", "NET-BEACON",
      "PROC-XHANDLE", "NET-PIPE", "MEM-HOLLOWED"],
    "Mythic (Apollo/Poseidon)": ["PROC-ENC-PS", "SIG-WEBSHELL-PHP", "FILE-WEBROOT-SHELL",
      "SIG-DOTNET-OFFTOOL", "PROC-NOPS-AMSI", "SIG-AMSI-BYPASS",
      "NET-BEACON", "DNS-BEACON"],
    "Realm / imix": ["SIG-REALM-IMIX", "SIG-RUST-IMPLANT", "SIG-MUSL-ELF",
      "SIG-ELDRITCH-TOME", "MEM-SIG-REALM-IMIX", "MEM-SIG-MUSL-ELF",
      "MEM-SIG-RUST-IMPLANT", "MEM-SIG-ELDRITCH-TOME", "EVT-4688-TEMP"],
    "watershell-cpp": ["SIG-WATERSHELL", "SIG-MINGW", "PKT-SOCKET", "NET-LISTENER",
      "PROC-MASQ", "SPAWN-SHELL", "NET-PIPE", "TIME-STOMP"]
  };

  var STAGES = {
    "Initial access": ["FILE-IMPLANT-SIG", "FILE-TOME", "FILE-WEBROOT-SHELL",
      "PROC-LOLBIN-DOWNLOAD", "EVT-DEADDROP", "NET-DEADDROP"],
    "Execution": ["EVT-4688-SUSP", "PROC-SCRIPTHOST", "EVT-SCRIPTHOST", "SPAWN-SHELL",
      "PROG-IMPLANT-LAUNCH", "PROC-SUSP-PARENT", "EVT-SUSP-PARENT", "EVT-4688-TEMP"],
    "Persistence": ["PERS-RUNKEY", "PERS-SERVICE", "PERS-STARTUP", "PERS-TASK",
      "PERS-WMI-SUB", "EVT-7045", "EVT-4698", "EVT-4720"],
    "Defense evasion": ["TAMPER-DEFENDER", "TAMPER-AUDIT", "PROC-AUDIT-DISABLE",
      "EVT-AUDIT-DISABLE", "EVT-LOG-CLEAR", "PROC-LOG-CLEAR", "PROC-NOPS-AMSI",
      "SIG-AMSI-BYPASS", "TIME-STOMP", "NTDLL-TAMPER", "PROC-MASQ", "PROC-ENC-PS"],
    "Credential access": ["LSASS-HANDLE", "PROC-MIMIKATZ-CLI", "PROC-SAM-SAVE",
      "EVT-SAM-SAVE"],
    "Command & control": ["NET-BEACON", "DNS-BEACON", "ICMP-BEACON", "NET-PIPE",
      "PKT-SOCKET", "NET-LISTENER", "PROC-RMM-TOOL", "EVT-RMM-TOOL",
      "PROC-EGRESS-TOOL", "EVT-EGRESS-TOOL", "PROC-WINRM-SESSION"],
    "Implant actions / lateral": ["PROC-XHANDLE", "MEM-RWX-UNBACKED", "MEM-RWX-NEW",
      "MEM-PROMOTE", "MEM-HOLLOWED", "SYSCALL-STUB", "THREAD-HIJACK",
      "THREAD-UNBACKED", "STACK-UNBACKED", "HOOK-DLL", "MOD-SIDELOAD",
      "PROC-PSEXESVC", "EVT-PSEXESVC", "PROC-DEFENDER-SIDELOAD",
      "EVT-DEFENDER-SIDELOAD", "PROC-NETSH-FIREWALL", "EVT-NETSH-FIREWALL"]
  };

  /* ---------------- shared helpers --------------------------------------- */
  function fmtT(ts) { return ts ? new Date(ts * 1000).toTimeString().slice(0, 8) : "--:--:--"; }
  function sevColor(s) { return { critical: "#CD4246", high: "#EC9A3C", medium: "#FBD065",
                                  low: "#3FA6DA", info: "#5F6B7C" }[s] || "#5F6B7C"; }

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
  function region(body) {
    var r = mk("div", "lv-region");
    body.appendChild(r);
    return r;
  }
  function col(flex) {
    var c = mk("div", "lv-col"); c.style.flex = flex || "1";
    return c;
  }

  var CACHE = { hits: {}, alerts: [] };
  var openRule = null;      // drill-down: rule whose alerts are expanded

  /* one category block: header with live total + rows per FIRING rule */
  function categoryBlock(name, rules, kind) {
    var firing = rules.filter(function (r) { return (CACHE.hits[r] || 0) > 0; });
    var total = rules.reduce(function (n, r) { return n + (CACHE.hits[r] || 0); }, 0);
    var c = mk("div", "lv-card");
    c.style.borderLeftColor = total ? sevColor("critical") : "#5ba3d0";
    var t = mk("div", "ttl");
    t.textContent = name;
    if (total) {
      var b = mk("span", "lv-pill", total + " hits");
      b.style.cssText = "margin-left:8px;color:#FFC7C9;background:rgba(205,66,70,.2)";
      t.appendChild(b);
    }
    c.appendChild(t);

    if (!firing.length) {
      var none = mk("div", "lv-kv");
      none.appendChild(mk("span", "v", "no detections hit"));
      none.firstChild.style.color = "var(--fg4)";
      c.appendChild(none);
      return c;
    }
    firing.forEach(function (r) {
      var rw = mk("div", "lv-kv");
      rw.style.cssText = "cursor:pointer";
      var v = mk("span", "v", r);
      v.style.color = "var(--blue5)";
      var last = CACHE.alerts.filter(function (a) { return a.rule === r; })
        .reduce(function (m, a) { return Math.max(m, a.ts || 0); }, 0);
      var meta = mk("span");
      meta.style.cssText = "margin-left:auto;color:var(--fg3)";
      meta.textContent = (CACHE.hits[r] || 0) + "× · last " + fmtT(last);
      rw.appendChild(v); rw.appendChild(meta);
      c.appendChild(rw);
      rw.onclick = function () { openRule = (openRule === kind + ":" + r) ? null : kind + ":" + r; render(); };
      /* drill-down: the actual alerts for this rule */
      if (openRule === kind + ":" + r) {
        CACHE.alerts.filter(function (a) { return a.rule === r; })
          .sort(function (x, y) { return y.ts - x.ts; }).slice(0, 5)
          .forEach(function (a) {
            var d = a.data || {};
            var ar = mk("div", "lv-sub");
            ar.style.cssText = "padding:2px 0 2px 14px;color:var(--fg2);cursor:pointer";
            ar.textContent = "▸ " + fmtT(a.ts) + " " + (a.title || "").slice(0, 76) +
              (d.pid ? " · pid " + d.pid : "") + (d.peer ? " · " + d.peer : "");
            ar.title = a.why || "";
            ar.onclick = function (e) { e.stopPropagation(); openRule = null; render(); };
            c.appendChild(ar);
          });
      }
    });
    return c;
  }

  /* ---------------- Threat Intel: two owned panels ----------------------- */
  var intelBody = BODYINT();
  function BODYINT() {
    var views = $$(".pg-screen");
    var el = null;
    views.forEach(function (v) {
      var n = $(".pg-name", v);
      if (n && /Threat Intel/i.test(n.textContent || "")) el = v;
    });
    return el ? (el.querySelector(".lv-body") || el.querySelector("[data-live-body]")) : null;
  }

  var fwP = null, stP = null;
  if (intelBody) {
    var reg = region(intelBody);
    var lc = col("1"), rc = col("1");
    reg.appendChild(lc); reg.appendChild(rc);
    fwP = panel("detections by C2 framework — live", "click a rule for its alerts");
    stP = panel("detections by attack stage — live", "detection-based, not raw events");
    lc.appendChild(fwP); rc.appendChild(stP);
  }

  /* ---------------- Signatures: live alert feed -------------------------- */
  var sigBody = BODYSIG();
  function BODYSIG() {
    var views = $$(".pg-screen");
    var el = null;
    views.forEach(function (v) {
      var n = $(".pg-name", v);
      if (n && /Signatures/i.test(n.textContent || "")) el = v;
    });
    return el ? (el.querySelector(".lv-body") || el.querySelector("[data-live-body]")) : null;
  }
  var sigFeed = null;
  if (sigBody) {
    var sreg = region(sigBody);
    var sc = col("1");
    sreg.appendChild(sc);
    sigFeed = panel("live detection alerts — every rule that has fired",
                    "newest first · severity-colored");
    sc.appendChild(sigFeed);
  }

  /* ---------------- Dashboard: top detections ---------------------------- */
  var dashBody = BODYDASH();
  function BODYDASH() {
    var views = $$(".pg-screen");
    var el = null;
    views.forEach(function (v) {
      var n = $(".pg-name", v);
      if (n && /Dashboard/i.test(n.textContent || "")) el = v;
    });
    return el ? (el.querySelector(".lv-body") || el.querySelector("[data-live-body]")) : null;
  }
  var topP = null;
  if (dashBody) {
    var dreg = region(dashBody);
    var dc = col("1");
    dreg.appendChild(dc);
    topP = panel("top detections firing", "ranked by hits since sensor start");
    dc.appendChild(topP);
  }

  /* ---------------- render + poll ---------------------------------------- */
  function render() {
    if (fwP) {
      fwP._body.innerHTML = "";
      Object.keys(FRAMEWORKS).forEach(function (k) {
        fwP._body.appendChild(categoryBlock(k, FRAMEWORKS[k], "fw"));
      });
    }
    if (stP) {
      stP._body.innerHTML = "";
      Object.keys(STAGES).forEach(function (k) {
        stP._body.appendChild(categoryBlock(k, STAGES[k], "st"));
      });
    }
    if (sigFeed) {
      sigFeed._body.innerHTML = "";
      var live = CACHE.alerts.filter(function (a) {
        return !/^RESP-/.test(a.rule || "") && a.status !== "resolved";
      }).sort(function (x, y) { return y.ts - x.ts; }).slice(0, 16);
      if (!live.length) {
        sigFeed._body.appendChild(mk("div", "lv-empty", "no detections fired yet"));
      } else {
        live.forEach(function (a) {
          var rw = mk("div");
          rw.style.cssText = "display:flex;gap:10px;padding:3px 6px;border-bottom:1px solid #1C2127;" +
            "font:11.5px var(--mono);cursor:pointer";
          var t = mk("span", null, fmtT(a.ts)); t.style.cssText = "min-width:58px;color:var(--fg4)";
          var rl = mk("b", null, a.rule); rl.style.cssText = "min-width:150px;color:" + sevColor(a.severity);
          var d = mk("span", null, (a.title || "").slice(0, 80));
          d.style.cssText = "color:var(--fg2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
          rw.appendChild(t); rw.appendChild(rl); rw.appendChild(d);
          rw.title = a.why || "";
          rw.onclick = function () {
            var detail = rw.nextElementSibling;
            if (detail && detail.getAttribute("data-drill") === "1") { detail.remove(); return; }
            var why = mk("div", "lv-sub", a.why || "");
            why.setAttribute("data-drill", "1");
            why.style.cssText = "padding:4px 6px 8px 74px;color:var(--fg3)";
            rw.parentNode.insertBefore(why, rw.nextSibling);
          };
          sigFeed._body.appendChild(rw);
        });
      }
    }
    if (topP) {
      topP._body.innerHTML = "";
      var ranked = Object.keys(CACHE.hits)
        .filter(function (r) { return CACHE.hits[r] > 0 && !/^RESP-/.test(r); })
        .sort(function (a, b) { return CACHE.hits[b] - CACHE.hits[a]; }).slice(0, 10);
      if (!ranked.length) {
        topP._body.appendChild(mk("div", "lv-empty", "no detections yet"));
        return;
      }
      var max = CACHE.hits[ranked[0]] || 1;
      ranked.forEach(function (r) {
        var last = CACHE.alerts.filter(function (a) { return a.rule === r; })
          .reduce(function (m, a) { return Math.max(m, a.ts || 0); }, 0);
        var row = mk("div");
        row.style.cssText = "display:flex;align-items:center;gap:8px;padding:3px 4px;" +
          "border-bottom:1px solid #1C2127;font:11.5px var(--mono)";
        var nm = mk("b", null, r); nm.style.cssText = "min-width:170px;color:var(--blue5)";
        var barW = mk("div");
        barW.style.cssText = "flex:1;height:6px;border:1px solid var(--line);border-radius:3px;overflow:hidden";
        var bar = mk("div");
        bar.style.width = Math.round(100 * CACHE.hits[r] / max) + "%";
        bar.style.cssText += ";height:100%;background:#EC9A3C";
        barW.appendChild(bar);
        var n = mk("span", null, CACHE.hits[r] + "×");
        n.style.cssText = "min-width:40px;text-align:right;color:var(--fg)";
        var lt = mk("span", null, "last " + fmtT(last));
        lt.style.cssText = "min-width:92px;text-align:right;color:var(--fg4)";
        row.appendChild(nm); row.appendChild(barW); row.appendChild(n); row.appendChild(lt);
        topP._body.appendChild(row);
      });
    }
  }

  function tick() {
    getJSON("/api/state").then(function (s) {
      CACHE.hits = s.rule_hits || {};
      CACHE.alerts = (s.alerts || []).slice(-500);
      render();
    }).catch(function () {});
  }
  tick();
  setInterval(tick, 3000);
})();
