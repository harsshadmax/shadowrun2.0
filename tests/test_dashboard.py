import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from shadowrun import api, audit, config, db, doctor, ui

DASH = config.ROOT / "dashboard"
TEMPLATES = sorted((DASH / "templates").glob("*.html"))
JS = (DASH / "static" / "app.js").read_text()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "ui.db")
    monkeypatch.setattr(api, "TOKEN", "test-token")
    from shadowrun import health
    health.reset_for_tests()
    monkeypatch.setattr(ui, "_ui_refresh", {"ts": 0.0})
    monkeypatch.setattr(doctor, "run_checks", lambda: [{"n": 1, "name": "docker", "ok": True, "detail": "ok"}])
    db.init_db()
    return TestClient(api.app, raise_server_exceptions=False)


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


def test_every_template_url_maps_to_a_route(client):
    urls = template_urls()
    assert len(urls) >= 8
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


def test_pages_render_with_header_strip_and_states(client):
    for path in ("/", "/demo"):
        r = client.get(path)
        assert r.status_code == 200
        assert "SIMULATED SCENARIOS ONLY" in r.text and "does not prove safety" in r.text
        assert 'content="test-token"' in r.text
    gate = client.get("/").text
    assert "Choose a scenario" in gate and "report-export-pro" in gate and "Loading runs" in gate
    demo = client.get("/demo").text
    assert "Verify chain" in demo and "Loading benchmark" in demo and "SIMULATED AGENT" in demo


def test_empty_and_populated_fragments(client):
    assert "No runs yet" in client.get("/ui/runs").text
    db.insert_run("r1", agent_id="cli", package_name="csvtoolkit", package_version="1.0.0", setup="shadowrun",
                  state="DECIDED", decision="BLOCK", decision_ms=2500)
    t = client.get("/ui/runs").text
    assert "Blocked" in t and "2.5s" in t and "csvtoolkit" in t and "#r1" in t
    assert "No runs match this filter" in client.get("/ui/runs?f=allow").text


def test_runs_fragment_escapes_untrusted_strings(client):
    evil = '<img src=x onerror=alert(1)>'
    db.insert_run("x1", agent_id='"><script>alert(2)</script>', package_name=evil, package_version="<b>1</b>",
                  setup="shadowrun", state="DECIDED", decision="ALLOW")
    t = client.get("/ui/runs").text
    assert "<script>" not in t and "<img src=x" not in t and "<b>1</b>" not in t
    assert "&lt;img src=x onerror=alert(1)&gt;" in t and "&lt;script&gt;" in t


def test_js_never_uses_innerhtml():
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", JS)


def test_doctor_fragment_pass_and_fail(client, monkeypatch):
    assert "ALL PASS" in client.get("/ui/doctor").text
    monkeypatch.setattr(ui, "_doctor_cache", {"ts": 0.0, "checks": None})
    monkeypatch.setattr(doctor, "run_checks", lambda: [{"n": 3, "name": "no internet", "ok": False, "detail": "<b>reached</b>"}])
    t = client.get("/ui/doctor").text
    assert "FAILED" in t and "shadowrun doctor" in t and "<b>reached</b>" not in t


def test_audit_fragment_ok_then_broken(client, tmp_path):
    for i in range(3):
        audit.append("ACTION_RECEIVED", f"r{i}", {"i": i})
    assert "Chain OK: 3 entries" in client.get("/ui/audit-verify").text
    con = sqlite3.connect(config.DB_PATH)
    con.execute("UPDATE audit_log SET payload_json='{}' WHERE id=2")
    con.commit()
    con.close()
    assert "BROKEN at entry 2" in client.get("/ui/audit-verify").text


def test_error_states_present_in_js():
    for needle in ("Cannot reach the Shadow-Run API", "shadowrun doctor", "Live stream interrupted",
                   "Benchmark not run yet", "No agent activity yet"):
        assert needle in JS or needle in (DASH / "templates" / "demo.html").read_text()


def seed(run_id, name, decision, ms, rules=(), setup="shadowrun", agent="cli"):
    from shadowrun.models import Finding
    db.insert_run(run_id, agent_id=agent, package_name=name, package_version="1.0.0", setup=setup, state="DECIDED",
                  decision=decision, decision_ms=ms, sha256="ab" * 32, phase_ms_json='{"fetch_ms": 5, "sandbox_ms": 2100}')
    db.add_findings(run_id, [Finding(rule_id=r, severity="high", message=f"{r} happened") for r in rules])


def test_kpis_and_note_fragments(client):
    assert "no scans yet" in client.get("/ui/kpis").text and "No scans yet" in client.get("/ui/note").text
    seed("a", "report-export-pro", "BLOCK", 2500, ["CANARY_READ", "NET_OUTBOUND"])
    seed("b", "csvtoolkit", "ALLOW", 2600)
    seed("c", "gitversion", "ESCALATE", 3000, ["UNEXPECTED_EXEC"])
    seed("d", "report-export-pro", "NONE", None, setup="no_guard")  # unguarded runs are not scans
    k = client.get("/ui/kpis").text
    assert ">3<" in k and "33% of scans" in k and "median 2.6s" in k
    assert "1 run needs human review" in client.get("/ui/note").text


def test_heatmap_fragment_counts_runs_per_rule_and_package(client):
    seed("a", "report-export-pro", "BLOCK", 2500, ["CANARY_READ", "NET_OUTBOUND"])
    seed("a2", "report-export-pro", "BLOCK", 2700, ["CANARY_READ"])
    seed("b", "csvtoolkit", "ALLOW", 2600)
    t = client.get("/ui/heatmap?tab=findings").text
    assert 'title="CANARY_READ · report-export-pro: 2"' in t and 'title="NET_OUTBOUND · report-export-pro: 1"' in t
    assert 'title="CANARY_READ · csvtoolkit: 0"' in t
    assert "Fastest decision" in t and "2.5s" in t and "2.7s" in t
    d = client.get("/ui/heatmap?tab=decisions").text
    assert 'title="BLOCK · report-export-pro: 2"' in d and 'title="ALLOW · csvtoolkit: 1"' in d
    assert 'title="CANARY_READ · report-export-pro: 2"' in client.get("/ui/heatmap?tab=bogus").text  # falls back


def test_heatmap_empty_state(client):
    assert "No scans yet" in client.get("/ui/heatmap").text


def test_run_detail_fragment_and_latest(client):
    assert "No runs yet" in client.get("/ui/run/latest").text
    seed("zz1", "reqeusts", "BLOCK", 2700, ["PERSISTENCE_WRITE"])
    t = client.get("/ui/run/zz1").text
    assert "#zz1" in t and "reqeusts" in t and "PERSISTENCE_WRITE" in t and "Sandbox install" in t and "2.1s" in t
    assert "Blocked" in t and "limited" in t
    assert "#zz1" in client.get("/ui/run/latest").text
    assert "No runs yet" in client.get("/ui/run/does-not-exist").text


def test_detail_and_heatmap_escape_untrusted(client):
    evil = "<script>alert(1)</script>"
    seed("x9", evil, "BLOCK", 2000, ["CANARY_READ"])
    for url in ("/ui/run/x9", "/ui/heatmap?tab=findings", "/ui/runs"):
        t = client.get(url).text
        assert "<script>alert(1)" not in t, url


def test_isolation_and_agent_fragments(client):
    t = client.get("/ui/isolation").text
    assert "Isolation" in t and "Internet" in t and "<svg" in t
    assert "No agent run yet" in client.get("/ui/agent").text
    db.add_agent_event("scripted-agent", None, "PROPOSE", "Use <b>x</b>")
    a = client.get("/ui/agent").text
    assert "PROPOSE" in a and "<b>x</b>" not in a and "SIMULATED AGENT" in a


def test_export_csv_and_formula_neutralised(client):
    seed("e1", "=HYPERLINK(\"http://evil\")", "BLOCK", 2000)
    r = client.get("/api/v1/runs/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    body = r.text
    assert body.splitlines()[0].startswith("id,created_at,agent_id,package_name")
    assert "'=HYPERLINK" in body and ",=HYPERLINK" not in body


def test_eval_results_empty_state_route(client):
    r = client.get("/api/v1/eval/results").json()
    assert "available" in r
