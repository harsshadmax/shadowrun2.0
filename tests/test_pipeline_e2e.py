"""End-to-end through the real sandbox. Needs `shadowrun up` (sink + pypiserver) and Docker; skipped otherwise.
Fixtures are hand-assembled by packages/build_all.py (never built on the host) and only read fake files / post to `sink`."""
import subprocess
import sys
import urllib.request

import pytest
import yaml

from shadowrun import audit, config, db, pipeline

MANIFESTS = [yaml.safe_load(p.read_text()) for p in sorted((config.ROOT / "packages" / "src").glob("*/MANIFEST.yaml"))]


def _up():
    try:
        urllib.request.urlopen(config.PYPI_URL + "/", timeout=2)
        import docker
        docker.from_env().containers.get("sink")
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason="sandbox services not up (run scripts/up.sh)")


@pytest.fixture(scope="module", autouse=True)
def dist_and_db(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    mp.setattr(config, "DB_PATH", tmp_path_factory.mktemp("db") / "e2e.db")
    subprocess.check_call([sys.executable, str(config.ROOT / "packages" / "build_all.py")], stdout=subprocess.DEVNULL)
    yield
    mp.undo()


def rules(run):
    return {f["rule_id"] for f in run["findings"]}


@pytest.mark.parametrize("m", MANIFESTS, ids=lambda m: m["id"])
def test_each_fixture_behaves_as_manifest_says(m):
    run = pipeline.run_action(m["name"])
    assert run["error"] is None, run
    assert run["decision"] == m["expected_decision"], (m["id"], run["decision_reason"], rules(run))
    assert set(m["expected_rules"]) <= rules(run), (m["id"], rules(run))
    if m["expected_decision"] == "ALLOW":
        assert run["findings"] == [], (m["id"], run["findings"])


def test_malicious_fixture_decision_details():
    run = pipeline.run_action("report-export-pro")
    assert run["decision_ms"] > 0
    assert {"block_exfil", "block_secrets"} <= set(run["decision_obj"].matched_rules)


def test_tampered_pin_is_rejected():
    run = pipeline.run_action("csvtoolkit", pin_sha256="0" * 64)
    assert "HASH_MISMATCH" in rules(run)
    assert run["decision"] == "BLOCK"


def test_unknown_package_fails_closed():
    run = pipeline.run_action("does-not-exist")
    assert run["error"] and run["decision"] == "ESCALATE"


def test_doctor_failure_refuses_to_run(monkeypatch):
    def boom(force=False):
        raise pipeline.DoctorFailed("doctor failed")
    monkeypatch.setattr(pipeline, "ensure_doctor", boom)
    run = pipeline.run_action("csvtoolkit")
    assert run["decision"] == "BLOCK" and run["findings"] == []


def test_audit_chain_after_runs():
    res = audit.verify()
    assert res["ok"] is True and res["checked"] > 10
