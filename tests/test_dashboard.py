import json
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from shadowrun import api, audit, config, db, doctor, health, ui
from shadowrun.models import Finding

DASH = config.ROOT / "dashboard"
TEMPLATES = sorted((DASH / "templates").glob("*.html"))
JS = (DASH / "static" / "app.js").read_text()
H = {"X-Demo-Token": "test-token"}
CHECK_NAMES = ["docker", "internal net", "no internet", "sink", "strace", "read-only root", "registry", "evidence"]


def checks(*oks):
    oks = oks or (True,) * 8
    return [{"n": i + 1, "name": CHECK_NAMES[i], "ok": ok, "detail": f"detail {i + 1}"} for i, ok in enumerate(oks)]


@pytest.fixture
def fake(monkeypatch):
    state = {"result": checks(), "calls": 0}

    def run_checks():
        state["calls"] += 1
        return list(state["result"])
    monkeypatch.setattr(doctor, "run_checks", run_checks)
    return state


@pytest.fixture
def client(tmp_path, monkeypatch, fake):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "ui.db")
    monkeypatch.setattr(api, "TOKEN", "test-token")
    monkeypatch.setattr(ui, "_ui_refresh", {"ts": 0.0})
    health.reset_for_tests()
    db.init_db()
    yield TestClient(api.app, raise_server_exceptions=False)
    health.reset_for_tests()


def _flatten(routes):
    for r in routes:
        if getattr(r, "path_regex", None):
            yield r
        # newer FastAPI wraps include_router() results (no prefix is used for the dashboard router)
        inner = (getattr(r, "routes", None) or getattr(getattr(r, "router", None), "routes", None)
                 or getattr(getattr(r, "original_router", None), "routes", None))
        if inner:
            yield from _flatten(inner)


def route_for(path: str, method: str = "GET"):
    for r in _flatten(api.app.routes):
        if r.path_regex.match(path):
            methods = getattr(r, "methods", None)
            if methods is None or method in methods:
                return r
    return None


def template_urls():
    urls = []
    for t in TEMPLATES:
        text = t.read_text()
        for attr, val in re.findall(r'\b(hx-get|hx-post|href|src|action)="(/[^"]*)"', text):
            urls.append((t.name, "POST" if attr == "hx-post" else "GET", val))
    return urls


def js_urls():
    out = []
    for m in re.finditer(r'"(/(?:api/v1|ui|static)[^"]*)"', JS):
        lit, rest = m.group(1), JS[m.end():m.end() + 160]
        call = JS[max(0, m.start() - 8):m.start()].endswith("api(")
        path = lit.split("?")[0]
        if "?" not in lit:
            c = re.match(r'\s*\+\s*[^+;,)\n]*(?:\([^)]*\))?\s*(?:\+\s*"([^"]*)")?', rest)
            if c and lit.endswith("/"):
                path = lit + "x" + (c.group(1) or "")
        method = "GET"
        if call and re.search(r'method:\s*"POST"', JS[m.end():m.end() + 140].split(");")[0].split(").then")[0]):
            method = "POST"
        out.append((method, path))
    return out


def seed(run_id, name, decision, ms=2500, rules=(), setup="shadowrun", agent="cli", created=None, report=None,
         phases='{"fetch_ms": 5, "sandbox_ms": 2100, "analyze_ms": 300}', version="1.0.0"):
    extra = {"created_at": created} if created else {}
    db.insert_run(run_id, agent_id=agent, package_name=name, package_version=version, setup=setup, state="DECIDED",
                  decision=decision, decision_ms=ms, sha256="ab" * 32, phase_ms_json=phases,
                  report_json=json.dumps(report or {}), **extra)
    db.add_findings(run_id, [Finding(rule_id=r, severity="high", message=f"{r} happened") for r in rules])


def ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).isoformat()


# ------------------------------------------------------------------ structure, URLs, safety

def test_every_template_url_maps_to_a_route(client):
    urls = template_urls()
    assert len(urls) >= 20
    for name, method, url in urls:
        path = url.split("#")[0].split("?")[0]
        if path.startswith("/static/"):
            assert (DASH / "static" / path[len("/static/"):]).is_file(), (name, url)
        else:
            assert route_for(path, method), (name, method, url)


def test_every_js_url_maps_to_a_route(client):
    urls = js_urls()
    assert len(urls) >= 8
    for method, path in urls:
        assert route_for(path, method), (method, path)


def test_js_never_builds_html_from_data_and_templates_have_no_inline_handlers():
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", JS)
    for t in TEMPLATES:
        assert "onclick=" not in t.read_text(), t.name


def test_pages_render_with_chrome_and_states(client):
    for path in ("/", "/demo"):
        r = client.get(path)
        assert r.status_code == 200
        assert "SIMULATED SCENARIOS ONLY" in r.text and "does not prove safety" in r.text
        assert 'content="test-token"' in r.text
    gate = client.get("/").text
    for needle in ("Install verdicts", "Choose a scenario", "report-export-pro", "Loading runs", "Scan activity",
                   "Sandbox health", "Detection matrix", "Recent verdicts", "Export CSV"):
        assert needle in gate, needle
    demo = client.get("/demo").text
    for needle in ("Verify chain", "Loading benchmark", "SIMULATED AGENT", "Start demo"):
        assert needle in demo, needle


# ------------------------------------------------------------------ runs table, search, escaping

def test_runs_fragment_empty_and_populated(client):
    assert "No runs yet" in client.get("/ui/runs").text
    seed("r1", "csvtoolkit", "BLOCK", 2500)
    t = client.get("/ui/runs").text
    assert "Blocked" in t and "2.5s" in t and "csvtoolkit" in t and "#r1" in t
    assert "No runs match this filter" in client.get("/ui/runs?f=allow").text


def test_search_matches_name_id_agent_and_treats_wildcards_literally(client):
    seed("id001", "a_b", "ALLOW")
    seed("id002", "axb", "ALLOW", agent="scripted-agent")
    seed("id003", "100%pure", "ALLOW")
    assert "a_b" in client.get("/ui/runs?q=a_b").text and "axb" not in client.get("/ui/runs?q=a_b").text
    assert "100%pure" in client.get("/ui/runs?q=%25").text and "axb" not in client.get("/ui/runs?q=%25").text
    assert "axb" in client.get("/ui/runs?q=scripted").text and "a_b" not in client.get("/ui/runs?q=scripted").text
    assert "id003" in client.get("/ui/runs?q=id003").text
    assert 'No runs match "nothing-here".' in client.get("/ui/runs?q=nothing-here").text
    assert "<script>" not in client.get("/ui/runs?q=%3Cscript%3E").text


def test_untrusted_strings_are_escaped_everywhere(client):
    evil = "<script>alert(1)</script>"
    img = '"><img src=x onerror=alert(2)>'
    seed("x9", evil, "BLOCK", rules=["CANARY_READ"], agent=img, version="<b>9</b>")
    for url in ("/ui/run/x9", "/ui/heatmap?tab=findings&window=all", "/ui/runs", "/ui/recent", "/ui/runs?q=" + "%3Cscript%3E",
                "/ui/cards?window=all"):
        t = client.get(url).text
        assert "<script>alert(1)" not in t and "<img src=x" not in t and "<b>9</b>" not in t, url


# ------------------------------------------------------------------ cards and windows

def test_cards_empty_state(client):
    t = client.get("/ui/cards?window=7d").text
    assert t.count('class="tile ') == 3 and "no blocked runs in this window" in t


def test_cards_count_only_scans_in_the_window_and_compare_to_previous(client):
    seed("n1", "a", "BLOCK", created=ago(hours=1))
    seed("n2", "b", "BLOCK", created=ago(hours=2))
    seed("n3", "c", "ALLOW", created=ago(hours=3))
    seed("old", "d", "BLOCK", created=ago(hours=30))  # previous 24h window
    seed("older", "e", "BLOCK", created=ago(days=10))  # only in "all"
    seed("unguarded", "f", "NONE", setup="no_guard", created=ago(hours=1))  # not a scan
    c = __import__("shadowrun.stats", fromlist=["cards"]).cards("24h")
    by = {x["decision"]: x for x in c["cards"]}
    assert (by["BLOCK"]["count"], by["ALLOW"]["count"], by["ESCALATE"]["count"]) == (2, 1, 0)
    assert by["BLOCK"]["delta"] == 1 and by["ALLOW"]["delta"] == -0 + 1 and c["total"] == 3
    assert sum(by["BLOCK"]["series"]) == 2 and len(by["BLOCK"]["series"]) == 12
    allc = __import__("shadowrun.stats", fromlist=["cards"]).cards("all")
    assert {x["decision"]: x["count"] for x in allc["cards"]}["BLOCK"] == 4 and allc["cards"][0]["delta"] is None
    t = client.get("/ui/cards?window=24h").text
    assert "+1 vs previous 24 hours" in t and "Runs in window" in t


def test_cards_window_param_and_invalid_value(client):
    seed("old", "d", "BLOCK", created=ago(days=3))
    assert 'tile-num">0<' in client.get("/ui/cards?window=24h").text
    assert 'tile-num">1<small>100%' in client.get("/ui/cards?window=7d").text
    assert 'tile-num">0<' in client.get("/ui/cards?window=bogus").text  # falls back to 24h


def test_indeterminate_runs_are_counted_and_labelled(client):
    seed("i1", "csvtoolkit", "ESCALATE", rules=["INCOMPLETE_TRACE"])
    seed("b1", "bad", "BLOCK", rules=["CANARY_READ", "INCOMPLETE_TRACE"])
    runs = client.get("/ui/runs").text
    assert runs.count("Indeterminate") == 1  # the BLOCK stays Blocked
    assert "indeterminate (evidence incomplete)" in client.get("/ui/cards?window=7d").text
    assert "Indeterminate" in client.get("/ui/run/i1").text and "Indeterminate" not in client.get("/ui/run/b1").text


def test_badge_counts_runs_needing_review(client):
    assert "badge-n" not in client.get("/ui/badge").text
    seed("e1", "x", "ESCALATE")
    seed("e2", "y", "ESCALATE")
    t = client.get("/ui/badge").text
    assert 'badge-n">2<' in t and "2 runs need human review" in t


# ------------------------------------------------------------------ matrix, detail, sidebar

def test_heatmap_counts_runs_per_rule_and_package(client):
    seed("a", "report-export-pro", "BLOCK", rules=["CANARY_READ", "NET_OUTBOUND"])
    seed("a2", "report-export-pro", "BLOCK", rules=["CANARY_READ"])
    seed("b", "csvtoolkit", "ALLOW")
    t = client.get("/ui/heatmap?tab=findings&window=all").text
    assert 'title="CANARY_READ · report-export-pro: 2"' in t and 'title="NET_OUTBOUND · report-export-pro: 1"' in t
    assert 'title="CANARY_READ · csvtoolkit: 0"' in t and "Fastest decision" in t
    assert "EVIDENCE_TAMPERED" not in t  # rules that never fired are hidden
    d = client.get("/ui/heatmap?tab=decisions&window=all").text
    assert 'title="BLOCK · report-export-pro: 2"' in d and 'title="ALLOW · csvtoolkit: 1"' in d
    assert 'title="CANARY_READ · report-export-pro: 2"' in client.get("/ui/heatmap?tab=bogus&window=all").text


def test_heatmap_window_and_empty_state(client):
    assert "No scans in this window" in client.get("/ui/heatmap?window=24h").text
    seed("o", "old-pkg", "BLOCK", rules=["CANARY_READ"], created=ago(days=3))
    assert "No scans in this window" in client.get("/ui/heatmap?window=24h").text
    assert "old-pkg" in client.get("/ui/heatmap?window=all").text


def test_heatmap_shows_evidence_rules_once_they_fire(client):
    seed("t1", "pkg", "ESCALATE", rules=["INCOMPLETE_TRACE", "EVIDENCE_UNAVAILABLE"])
    t = client.get("/ui/heatmap?window=all").text
    assert "INCOMPLETE_TRACE" in t and "EVIDENCE_UNAVAILABLE" in t


def test_run_detail_shows_timeline_evidence_and_integrity(client):
    rep = {"evidence": {"trusted": True, "sha256": "f" * 64, "bytes": 1234, "errors": [], "tampered": []},
           "trace_lines": 77, "trace_problems": [], "doctor": {"id": "dd11", "checked_at": "2026-01-01T10:20:30+00:00", "ok": True}}
    seed("zz1", "reqeusts", "BLOCK", rules=["PERSISTENCE_WRITE"], report=rep)
    t = client.get("/ui/run/zz1").text
    assert "#zz1" in t and "reqeusts" in t and "PERSISTENCE_WRITE" in t and "Sandbox" in t and "2.1s" in t
    assert "1234 bytes · 77 lines" in t and "ffffffffffffffff" in t and "complete" in t
    assert "Gated by check" in t and "#dd11" in t and "10:20:30" in t
    assert "#zz1" in client.get("/ui/run/latest").text
    assert "No runs yet" in client.get("/ui/run/does-not-exist").text


def test_detail_untrusted_and_incomplete_trace_is_visible(client):
    rep = {"evidence": {"trusted": False, "sha256": None, "bytes": 0, "errors": ["trace file missing"], "tampered": []},
           "trace_lines": 0, "trace_problems": ["trace is empty"]}
    seed("u1", "pkg", "ESCALATE", rules=["EVIDENCE_UNAVAILABLE"], report=rep)
    t = client.get("/ui/run/u1").text
    assert "Trace trusted" in t and "trace is empty" in t and ">no<" in t


def test_sidebar_recent_list(client):
    assert "No verdicts yet" in client.get("/ui/recent").text
    for i in range(6):
        seed(f"s{i}", f"pkg{i}", "ALLOW", created=ago(minutes=60 - i))
    t = client.get("/ui/recent").text
    assert t.count("recent-item") == 4 and "pkg5" in t and "pkg1" not in t


# ------------------------------------------------------------------ BUG 1: one honest health status

def test_unknown_before_first_check_when_busy(client, fake):
    # a scan holds the sandbox: the dashboard must not start a doctor check, and must say UNKNOWN
    release = threading.Event()
    started = threading.Event()

    def scan():
        with health.RUN_LOCK:
            started.set()
            release.wait(5)
    th = threading.Thread(target=scan)
    th.start()
    started.wait(2)
    try:
        t = client.get("/ui/health").text
        assert "UNKNOWN" in t and "No check has run yet" in t and "disabled" in t
        assert "scan in progress" in client.get("/ui/doctor").text
        assert fake["calls"] == 0, "the dashboard ran a doctor check during a scan"
    finally:
        release.set()
        th.join()


def test_pass_state_shows_id_time_and_every_check(client):
    pill = client.get("/ui/doctor").text
    panel = client.get("/ui/health").text
    s = health.peek()
    assert s["state"] == "PASS" and "Doctor PASS" in pill and s["finished_at"][11:19] in pill
    assert f"#{s['id']}" in panel and s["finished_at"][11:19] in panel
    for name in CHECK_NAMES:
        assert name in panel
    assert panel.count("chip ok") >= 9  # overall + eight checks


def test_pill_and_panel_always_describe_the_same_check(client, fake):
    client.get("/ui/doctor")
    first = health.peek()["id"]
    health.refresh("test")  # a newer check appears
    second = health.peek()["id"]
    assert first != second
    assert f"#{second}" in client.get("/ui/health").text and f"#{first}" not in client.get("/ui/health").text


def test_failed_check_is_fail_not_pass_anywhere(client, fake):
    fake["result"] = checks(True, True, True, True, False, True, True, True)
    pill, panel = client.get("/ui/doctor").text, client.get("/ui/health").text
    assert "Doctor FAIL" in pill and "chip ok" not in pill
    assert "Runs are refused" in panel and "strace" in panel and panel.count("chip bad") >= 2


def test_stale_status_is_labelled_stale_and_checks_are_not_shown_as_current(client, fake, monkeypatch):
    health.refresh("seed")
    monkeypatch.setattr(ui, "_ui_refresh", {"ts": time.time()})  # dashboard re-check throttled, so STALE is visible
    health.invalidate("run abc: evidence anomaly")
    t = client.get("/ui/health").text
    assert "STALE" in t and "not current" in t and "evidence anomaly" in t and t.count("stale") >= 8
    assert "chip ok" not in t


def test_dashboard_rechecks_when_idle_and_not_fresh_pass(client, fake):
    health.refresh("seed")
    health.invalidate("anomaly")
    client.get("/ui/health")
    assert health.peek()["state"] == "PASS" and fake["calls"] == 2


def test_dashboard_recheck_is_throttled(client, fake):
    fake["result"] = checks(False, True)
    client.get("/ui/health")
    client.get("/ui/health")
    client.get("/ui/doctor")
    assert fake["calls"] == 1  # a failing doctor is not hammered on every poll


def test_run_detail_never_merges_its_check_with_the_current_one(client, fake):
    health.refresh("seed")
    old_id = health.peek()["id"]
    seed("c1", "pkg", "ALLOW", report={"doctor": {"id": old_id, "checked_at": "2026-01-01T00:00:00+00:00", "ok": True}})
    assert "same check" in client.get("/ui/run/c1").text
    health.refresh("newer")
    t = client.get("/ui/run/c1").text
    assert "newer check passed since" in t and "same check" not in t
    fake["result"] = checks(True, False)
    health.refresh("failing")
    t = client.get("/ui/run/c1").text
    assert "sandbox health now: FAIL" in t
    health.invalidate("x")  # a failing status stays FAIL; invalidation only demotes a PASS
    assert "sandbox health now: FAIL" in client.get("/ui/run/c1").text
    fake["result"] = checks()
    health.refresh("recovered")
    health.invalidate("x")
    assert "sandbox health now: STALE" in client.get("/ui/run/c1").text
    seed("c2", "pkg2", "ALLOW")  # a run with no recorded check is UNKNOWN, never assumed PASS
    t2 = client.get("/ui/run/c2").text
    assert "UNKNOWN" in t2 and "no recorded doctor check" in t2


def test_api_doctor_status_and_refresh(client, fake):
    r = client.get("/api/v1/doctor").json()
    assert r["state"] == "UNKNOWN" and r["busy"] is False and fake["calls"] == 0  # reading never runs a check
    assert client.post("/api/v1/doctor/refresh").status_code == 401
    r = client.post("/api/v1/doctor/refresh", headers=H).json()
    assert r["state"] == "PASS" and r["id"] and fake["calls"] == 1
    assert client.get("/api/v1/doctor").json()["id"] == r["id"]


def test_api_doctor_refresh_conflicts_with_a_running_scan(client, fake):
    release, started = threading.Event(), threading.Event()

    def scan():
        with health.RUN_LOCK:
            started.set()
            release.wait(5)
    th = threading.Thread(target=scan)
    th.start()
    started.wait(2)
    try:
        r = client.post("/api/v1/doctor/refresh", headers=H)
        assert r.status_code == 409 and fake["calls"] == 0
        assert client.get("/api/v1/doctor").json()["busy"] is True
    finally:
        release.set()
        th.join()


def test_concurrent_status_requests_do_not_corrupt_state(client, fake):
    results = []

    def hit():
        results.append(client.get("/ui/health").status_code)
    ts = [threading.Thread(target=hit) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results == [200] * 6 and health.peek()["state"] == "PASS"


# ------------------------------------------------------------------ misc fragments and endpoints

def test_agent_fragment(client):
    assert "No agent run yet" in client.get("/ui/agent").text
    db.add_agent_event("scripted-agent", None, "PROPOSE", "Use <b>x</b>")
    a = client.get("/ui/agent").text
    assert "PROPOSE" in a and "<b>x</b>" not in a and "SIMULATED AGENT" in a


def test_audit_fragment_ok_then_broken(client):
    for i in range(3):
        audit.append("ACTION_RECEIVED", f"r{i}", {"i": i})
    assert "Chain OK: 3 entries" in client.get("/ui/audit-verify").text
    con = sqlite3.connect(config.DB_PATH)
    con.execute("UPDATE audit_log SET payload_json='{}' WHERE id=2")
    con.commit()
    con.close()
    assert "BROKEN at entry 2" in client.get("/ui/audit-verify").text


def test_export_csv_and_formula_neutralised(client):
    seed("e1", '=HYPERLINK("http://evil")', "BLOCK")
    r = client.get("/api/v1/runs/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert r.text.splitlines()[0].startswith("id,created_at,agent_id,package_name")
    assert "'=HYPERLINK" in r.text and ",=HYPERLINK" not in r.text


def test_error_and_empty_states_exist_in_js_and_templates():
    for needle in ("Cannot reach the Shadow-Run API", "shadowrun doctor", "Live stream interrupted",
                   "Benchmark not run yet", "No agent activity yet", "INDETERMINATE"):
        assert needle in JS or needle in (DASH / "templates" / "demo.html").read_text(), needle


def test_eval_results_empty_state_route(client):
    assert "available" in client.get("/api/v1/eval/results").json()
