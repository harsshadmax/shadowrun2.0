import json
import subprocess
import sys
import time
import urllib.request

import pytest
from fastapi.testclient import TestClient

from shadowrun import api, audit, config, db

H = {"X-Demo-Token": "test-token"}


def _up():
    try:
        urllib.request.urlopen(config.PYPI_URL + "/", timeout=2)
        import docker
        docker.from_env().containers.get("sink")
        return True
    except Exception:
        return False


needs_sandbox = pytest.mark.skipif(not _up(), reason="sandbox services not up")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    mp.setattr(config, "DB_PATH", tmp_path_factory.mktemp("apidb") / "api.db")
    mp.setattr(api, "TOKEN", "test-token")
    db.init_db()
    if _up():
        subprocess.check_call([sys.executable, str(config.ROOT / "packages" / "build_all.py")], stdout=subprocess.DEVNULL)
    yield TestClient(api.app, raise_server_exceptions=False)
    mp.undo()


def test_health_and_error_envelope(client):
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    r = client.get("/api/v1/runs/nope")
    assert r.status_code == 404
    e = r.json()["error"]
    assert e["code"] == "http_404" and e["request_id"] and "Traceback" not in json.dumps(e)


def test_mutating_routes_need_token(client):
    for path, body in [("/api/v1/actions", {"spec": "x"}), ("/api/v1/demo/unguarded", {"spec": "x"}),
                       ("/api/v1/agent/run", {}), ("/api/v1/admin/demo-reset", {})]:
        assert client.post(path, json=body).status_code == 401
        assert client.post(path, json=body, headers={"X-Demo-Token": "wrong"}).status_code == 401
    assert client.post("/api/v1/actions", json={"nope": 1}, headers=H).json()["error"]["code"] == "invalid_request"


def test_audit_endpoints(client):
    assert client.get("/api/v1/audit/verify").json()["ok"] is True
    assert "entries" in client.get("/api/v1/audit").json()


@needs_sandbox
def test_actions_wait_blocks_malicious_and_sse_replays_phases(client):
    r = client.post("/api/v1/actions", json={"spec": "report-export-pro", "wait": True}, headers=H).json()
    assert r["decision"] == "BLOCK" and {"CANARY_READ", "NET_OUTBOUND", "CANARY_EXFIL"} <= {f["rule_id"] for f in r["findings"]}
    assert r["phases"]["sandbox_ms"] > 0
    with client.stream("GET", f"/api/v1/runs/{r['run_id']}/stream") as s:
        text = "".join(s.iter_text())
    kinds = [ln[7:] for ln in text.splitlines() if ln.startswith("event: ")]
    assert kinds[0] == "phase" and "finding" in kinds and kinds[-2:] == ["decision", "end"]
    assert client.get(f"/api/v1/runs/{r['run_id']}").json()["decision"] == "BLOCK"


@needs_sandbox
def test_actions_async_returns_202(client):
    r = client.post("/api/v1/actions", json={"spec": "csvtoolkit", "wait": False}, headers=H)
    assert r.status_code == 202
    rid = r.json()["run_id"]
    with client.stream("GET", f"/api/v1/runs/{rid}/stream") as s:
        text = "".join(s.iter_text())
    assert '"decision": "ALLOW"' in text


@needs_sandbox
def test_unguarded_demo_leaks_canary_to_sink(client):
    r = client.post("/api/v1/demo/unguarded", json={"spec": "report-export-pro"}, headers=H).json()
    assert r["error"] is None
    assert len(r["leaked_tokens"]) == 1 and r["leaked_tokens"][0].endswith("-ssh")
    assert any(r["leaked_tokens"][0] in json.dumps(e) for e in r["sink_events"])
    assert client.get("/api/v1/sink/events").json()["events"]


@needs_sandbox
def test_agent_blocked_then_switches_and_finishes(client):
    assert client.post("/api/v1/agent/run", json={}, headers=H).status_code == 202
    ev = []
    for _ in range(90):
        time.sleep(1)
        d = client.get("/api/v1/agent/events").json()
        ev = d["events"]
        if not d["running"] and ev:
            break
    kinds = [e["kind"] for e in ev]
    assert kinds == ["PROPOSE", "BLOCKED_NOTICE", "CHOOSE_ALT", "CONTINUE"], ev
    assert "report-export-pro" in ev[1]["message"] and "CANARY" in ev[1]["message"]
    assert "csvtoolkit" in ev[2]["message"] and ev[3]["run_id"]
    assert (config.DATA / "agent_workspace" / "report_export.py").exists()


@needs_sandbox
def test_demo_reset_keeps_audit_log(client):
    before = audit.verify()["checked"]
    assert client.post("/api/v1/admin/demo-reset", json={}, headers=H).json() == {"ok": True}
    assert client.get("/api/v1/runs").json()["runs"] == []
    assert client.get("/api/v1/agent/events").json()["events"] == []
    after = audit.verify()
    assert after["ok"] and after["checked"] == before and before > 0


@needs_sandbox
def test_cli_exit_codes(tmp_path):
    import os

    def run(spec):
        return subprocess.run([sys.executable, "-m", "shadowrun.cli", "pip", "install", spec],
                              capture_output=True, text=True, cwd=config.ROOT,
                              env={**os.environ, "SHADOWRUN_DB": str(tmp_path / "cli.db")})
    bad = run("report-export-pro")
    assert bad.returncode == 2 and "BLOCKED" in bad.stdout and "CANARY_READ" in bad.stdout
    good = run("csvtoolkit")
    assert good.returncode == 0 and "ALLOWED" in good.stdout and "limited" in good.stdout
