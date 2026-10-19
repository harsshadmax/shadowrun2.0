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
    monkeypatch.setattr(ui, "_doctor_cache", {"ts": 0.0, "checks": None})
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
        path = url.split("?")[0]
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
    assert "BLOCKED" in t and "2.5s" in t and "csvtoolkit" in t


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


def test_eval_results_empty_state_route(client):
    r = client.get("/api/v1/eval/results").json()
    assert "available" in r
