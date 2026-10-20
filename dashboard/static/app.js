/* Shadow-Run dashboard. All dynamic text is inserted with text nodes and createElement, never as raw HTML:
   package names, findings and sink contents are untrusted. */
(function () {
  "use strict";
  var TOKEN = (document.querySelector('meta[name="demo-token"]') || {}).content || "";
  var $ = function (s, r) { return (r || document).querySelector(s); };

  function h(tag, attrs) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "class") el.className = attrs[k]; else el.setAttribute(k, attrs[k]);
    });
    (function add(list) {
      list.forEach(function (c) {
        if (c == null) return;
        if (Array.isArray(c)) { add(c); return; }
        el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
      });
    })(Array.prototype.slice.call(arguments, 2));
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function secs(ms) { return (ms / 1000).toFixed(2) + "s"; }

  function api(path, opts) {
    opts = opts || {};
    var init = { method: opts.method || "GET", headers: { "X-Demo-Token": TOKEN } };
    if (opts.body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
    return fetch(path, init).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) {
          var e = new Error((j.error && j.error.message) || ("Request failed (" + r.status + ")"));
          e.status = r.status; throw e;
        }
        return j;
      });
    }, function () { throw new Error("Cannot reach the Shadow-Run API. Is `shadowrun serve` running?"); });
  }

  function showError(el, err) {
    var msg = err && err.message ? err.message : String(err);
    if (/docker|doctor|sandbox/i.test(msg)) msg += " Docker is not running or the sandbox is unhealthy. Run `shadowrun doctor`.";
    el.textContent = msg; el.hidden = false;
  }
  function hideError(el) { el.hidden = true; el.textContent = ""; }

  var VERDICT = {
    ALLOW: { cls: "allow", icon: "✔", title: "ALLOWED" },
    BLOCK: { cls: "block", icon: "✖", title: "BLOCKED" },
    ESCALATE: { cls: "escalate", icon: "⚠", title: "NEEDS HUMAN REVIEW (denied)" }
  };
  function setVerdict(el, kind, title, detail) {
    var v = VERDICT[kind] || { cls: kind, icon: "•", title: title };
    el.className = "verdict " + v.cls;
    clear(el);
    el.appendChild(h("span", { "class": "icon", "aria-hidden": "true" }, v.icon));
    el.appendChild(h("span", { "class": "text" }, h("strong", {}, title || v.title), detail || ""));
  }
  function findingItem(f) {
    return h("li", {}, h("span", { "class": "sev " + f.severity }, f.severity), h("span", { "class": "rule" }, f.rule_id), f.message);
  }
  function fillFindings(ul, list, emptyText) {
    clear(ul);
    if (!list.length) { ul.appendChild(h("li", { "class": "empty" }, emptyText)); return; }
    list.forEach(function (f) { ul.appendChild(findingItem(f)); });
  }

  function refreshAll() { document.body.dispatchEvent(new Event("refresh")); }

  /* ---------- every page: delegated handlers (fragments are re-rendered by htmx) ---------- */
  function initShared() {
    document.addEventListener("click", function (e) {
      var t = e.target.closest ? e.target : e.target.parentElement;
      var sc = t && t.closest("[data-scroll]");
      if (sc) { var dest = $(sc.getAttribute("data-scroll")); if (dest) dest.scrollIntoView({ behavior: "smooth", block: "start" }); }

      var re = t && t.closest("#recheck");
      if (re) {
        re.disabled = true;
        api("/api/v1/doctor/refresh", { method: "POST", body: {} })
          .then(refreshAll, function (err) { re.disabled = false; alert(err.message); });
      }

      var rs = t && t.closest("#reset-demo");
      if (rs && window.confirm("Clear runs, findings, agent events and the sink log? The audit log is kept.")) {
        api("/api/v1/admin/demo-reset", { method: "POST", body: {} }).then(function () { window.location.reload(); },
          function (err) { alert(err.message); });
      }
    });
    var win = $("#win");
    if (win) win.addEventListener("change", function () { document.body.dispatchEvent(new Event("wchange")); });
  }

  /* ---------- Overview: scan dialog + agent button ---------- */
  function initOverview() {
    var dlg = $("#scan");
    $("#open-scan").addEventListener("click", function () { dlg.showModal(); });
    $("#close-scan").addEventListener("click", function () { dlg.close(); });
    dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener("close", refreshAll);
    if (window.location.hash === "#scan") dlg.showModal();

    // the agent card is re-rendered by htmx, so listen on the document
    document.addEventListener("click", function (e) {
      var btn = e.target.closest && e.target.closest("#run-agent");
      if (!btn) return;
      btn.disabled = true;
      api("/api/v1/agent/run", { method: "POST", body: {} }).then(function () {
        var n = 0, t = setInterval(function () { refreshAll(); if (++n > 20) clearInterval(t); }, 2000);
      }).catch(function () { btn.disabled = false; });
    });
    initGate();
  }

  /* ---------- Live scan (inside the dialog) ---------- */
  function initGate() {
    var run = $("#run"), spec = $("#spec"), sel = $("#scenario"), err = $("#run-error");
    var verdict = $("#verdict"), findings = $("#findings");
    var steps = {};
    document.querySelectorAll("#stepper li").forEach(function (li) { steps[li.dataset.phase] = li; });

    function resetUI() {
      Object.keys(steps).forEach(function (k) { steps[k].className = ""; $(".sec", steps[k]).textContent = ""; });
      setVerdict(verdict, "loading", "Running…", " Fetching and analyzing in the sandbox.");
      fillFindings(findings, [], "Findings appear here as they are detected.");
    }
    function phase(p) {
      var li = steps[p.phase]; if (!li) return;
      li.className = p.state === "start" ? "active" : "done";
      if (p.state === "done" && p.ms != null) $(".sec", li).textContent = secs(p.ms);
    }

    sel.addEventListener("change", function () { if (sel.value) spec.value = sel.value; });
    run.addEventListener("click", function () {
      var s = spec.value.trim() || sel.value;
      hideError(err);
      if (!s) { showError(err, new Error("Choose a scenario or type a package spec first.")); return; }
      run.disabled = true; resetUI();
      var count = 0, finished = false;
      api("/api/v1/actions", { method: "POST", body: { spec: s, wait: false, agent_id: "dashboard" } }).then(function (r) {
        var es = new EventSource("/api/v1/runs/" + encodeURIComponent(r.run_id) + "/stream");
        es.addEventListener("phase", function (e) { phase(JSON.parse(e.data)); });
        es.addEventListener("finding", function (e) {
          var f = JSON.parse(e.data);
          if (count++ === 0) clear(findings);
          findings.appendChild(findingItem(f));
        });
        es.addEventListener("decision", function (e) {
          var d = JSON.parse(e.data); finished = true;
          steps.decide.className = "done"; $(".sec", steps.decide).textContent = secs(d.decision_ms);
          setVerdict(verdict, d.decision, d.indeterminate ? "INDETERMINATE (denied: evidence incomplete)" : null,
                     " " + d.reason + " (confidence: limited)");
          if (!count) fillFindings(findings, [], "No findings in the tested run.");
        });
        es.addEventListener("end", function () { es.close(); run.disabled = false; refreshAll(); });
        es.onerror = function () {
          es.close(); run.disabled = false;
          if (!finished) {
            setVerdict(verdict, "idle", "Connection lost", " The live stream ended before a decision arrived.");
            showError(err, new Error("Live stream interrupted."));
          }
        };
      }).catch(function (e) {
        run.disabled = false; setVerdict(verdict, "idle", "Not run", " " + e.message); showError(err, e);
      });
    });
  }

  /* ---------- Split-screen demo ---------- */
  var chart = null;
  function renderBench(data) {
    var box = $("#bench"); clear(box);
    if (!data.available || !data.rows || !data.rows.length) {
      box.appendChild(h("p", { "class": "empty" }, "Benchmark not run yet. Run `shadowrun eval` and reload."));
      return;
    }
    var head = ["Setup", "Attacks prevented", "Benign wrongly stopped", "Canary tokens leaked", "Median decision", "Max decision"];
    var tbl = h("table", {}, h("thead", {}, h("tr", {}, head.map(function (t) { return h("th", {}, t); }))));
    var body = h("tbody", {});
    data.rows.forEach(function (r) {
      body.appendChild(h("tr", {}, h("td", {}, r.setup),
        h("td", {}, r.attacks_prevented + " of " + r.attacks_total),
        h("td", {}, r.false_positives + " of " + r.benign_total),
        h("td", {}, String(r.leaked_tokens)),
        h("td", {}, r.median_ms == null ? "n/a" : secs(r.median_ms)),
        h("td", {}, r.max_ms == null ? "n/a" : secs(r.max_ms))));
    });
    tbl.appendChild(body);
    box.appendChild(h("div", { "class": "table-wrap" }, tbl));
    box.appendChild(h("p", { "class": "disclaimer" }, data.disclaimer || ""));
    if (data.phases && window.Chart) {
      var labels = Object.keys(data.phases), vals = labels.map(function (k) { return data.phases[k] / 1000; });
      var cs = getComputedStyle(document.documentElement);
      if (chart) chart.destroy();
      chart = new Chart($("#latency-chart"), {
        type: "bar",
        data: { labels: labels.map(function (l) { return l.replace("_ms", ""); }),
                datasets: [{ label: "Median seconds per phase (Shadow-Run)", data: vals, borderRadius: 8,
                             backgroundColor: cs.getPropertyValue("--lav").trim() }] },
        options: { responsive: true, plugins: { legend: { labels: { color: cs.getPropertyValue("--text").trim() } } },
                   scales: { x: { ticks: { color: cs.getPropertyValue("--muted").trim() } }, y: { beginAtZero: true, ticks: { color: cs.getPropertyValue("--muted").trim() } } } }
      });
    }
  }

  function initDemo() {
    var start = $("#start"), reset = $("#reset"), status = $("#demo-status"), err = $("#demo-error");
    var leftBody = $("#left-body"), rv = $("#right-verdict"), rf = $("#right-findings"), tr = $("#transcript");

    api("/api/v1/eval/results").then(renderBench, function () {
      var b = $("#bench"); clear(b); b.appendChild(h("p", { "class": "empty" }, "Benchmark results unavailable."));
    });

    function resetPanels() {
      clear(leftBody); leftBody.appendChild(h("p", { "class": "empty" }, "Press Start demo."));
      setVerdict(rv, "idle", "Waiting for the agent.", "");
      clear(rf); clear(tr); tr.appendChild(h("li", { "class": "empty" }, "No agent activity yet."));
    }
    reset.addEventListener("click", function () {
      hideError(err);
      api("/api/v1/admin/demo-reset", { method: "POST", body: {} }).then(function () {
        resetPanels(); status.textContent = "Demo reset."; document.body.dispatchEvent(new Event("refresh"));
      }).catch(function (e) { showError(err, e); });
    });

    function renderLeft(r) {
      clear(leftBody);
      if (r.error) { leftBody.appendChild(h("p", { "class": "error" }, r.error)); return; }
      leftBody.appendChild(h("p", {}, "Installed with no analysis."));
      if (r.leaked_tokens.length) {
        leftBody.appendChild(h("p", { "class": "leak", role: "alert" }, "✖ LEAKED: " + r.leaked_tokens.length + " secret(s) reached the attacker's sink"));
        leftBody.appendChild(h("p", { "class": "leak" }, r.leaked_tokens.join(", ")));
      } else {
        leftBody.appendChild(h("p", {}, "No canary tokens reached the sink."));
      }
      var log = r.sink_events.map(function (e) { return e.method + " " + e.path + "\n" + (e.body || ""); }).join("\n---\n");
      leftBody.appendChild(h("h3", {}, "What the sink received"));
      leftBody.appendChild(h("pre", { "class": "sinklog" }, log || "(nothing)"));
    }

    function showRun(runId) {
      return api("/api/v1/runs/" + encodeURIComponent(runId)).then(function (run) {
        setVerdict(rv, run.decision, null, " " + run.decision_reason);
        fillFindings(rf, run.findings, "No findings.");
      });
    }

    function pollAgent(baseline) {
      var seen = baseline || 0; clear(tr);
      return new Promise(function (resolve, reject) {
        (function tick() {
          api("/api/v1/agent/events?since_id=" + seen).then(function (d) {
            d.events.forEach(function (ev) {
              seen = ev.id;
              tr.appendChild(h("li", {}, h("span", { "class": "kind" }, ev.kind), ev.message));
              if (ev.kind === "BLOCKED_NOTICE" && ev.run_id) showRun(ev.run_id);
            });
            if (!d.running && seen > (baseline || 0)) resolve(); else setTimeout(tick, 1000);
          }).catch(reject);
        })();
      });
    }

    start.addEventListener("click", function () {
      hideError(err); start.disabled = true; reset.disabled = true;
      resetPanels(); clear(leftBody); leftBody.appendChild(h("p", { "class": "verdict loading" }, "Installing without a gate…"));
      status.textContent = "Running unguarded install…";
      api("/api/v1/demo/unguarded", { method: "POST", body: { spec: "report-export-pro" } }).then(function (r) {
        renderLeft(r); status.textContent = "Agent is working…";
        setVerdict(rv, "loading", "Analyzing…", " The agent submitted its install to the gate.");
        return api("/api/v1/agent/events?since_id=0");
      }).then(function (d) {
        var baseline = d.events.length ? d.events[d.events.length - 1].id : 0;  // only show this run's events
        return api("/api/v1/agent/run", { method: "POST", body: {} }).then(function () { return pollAgent(baseline); });
      }).then(function () {
        status.textContent = "Done."; document.body.dispatchEvent(new Event("refresh"));
      }).catch(function (e) { status.textContent = ""; showError(err, e); setVerdict(rv, "idle", "Demo stopped.", " " + e.message); })
        .then(function () { start.disabled = false; reset.disabled = false; });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var page = document.body.dataset.page;
    initShared();
    if (page === "overview") initOverview();
    if (page === "demo") initDemo();
  });
})();
