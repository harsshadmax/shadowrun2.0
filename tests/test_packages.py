"""Static checks on the fixtures (no Docker) plus the build guard rails."""
import subprocess
import sys
import tarfile
import zipfile

import pytest
import yaml

from packages import build_all  # noqa: F401  (packages/ is a namespace package at the repo root)
from shadowrun import config

SRC = config.ROOT / "packages" / "src"
MANIFESTS = [yaml.safe_load(p.read_text()) for p in sorted(SRC.glob("*/MANIFEST.yaml"))]


@pytest.fixture(scope="module", autouse=True)
def built():
    subprocess.check_call([sys.executable, str(config.ROOT / "packages" / "build_all.py")],
                          stdout=subprocess.DEVNULL)


def test_six_packages_with_expected_ids():
    assert sorted(m["id"] for m in MANIFESTS) == ["B1", "B2", "B3", "M1", "M2", "M3"]


@pytest.mark.parametrize("m", MANIFESTS, ids=lambda m: m["id"])
def test_manifest_and_names(m):
    assert "SIMULATED" in m["description"]
    assert "simulated" not in m["name"].lower()


@pytest.mark.parametrize("m", MANIFESTS, ids=lambda m: m["id"])
def test_every_py_file_has_header_and_artifact_exists(m):
    dist = config.ROOT / "packages" / "dist"
    arts = [p for p in dist.iterdir() if p.name.replace("_", "-").lower().startswith(m["name"].replace("_", "-").lower())]
    assert len(arts) == 1, arts
    art = arts[0]
    if m["form"] == "wheel":
        assert art.suffix == ".whl"
        texts = {n: zipfile.ZipFile(art).read(n).decode() for n in zipfile.ZipFile(art).namelist() if n.endswith(".py")}
    else:
        tf = tarfile.open(art)
        texts = {x.name: tf.extractfile(x).read().decode() for x in tf.getmembers() if x.name.endswith(".py")}
    assert texts
    for n, t in texts.items():
        assert t.startswith("# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX."), n
    assert "MANIFEST.yaml" not in " ".join(tarfile.open(art).getnames() if m["form"] == "sdist" else [])


def test_benign_fixtures_have_no_payload_markers():
    for m in MANIFESTS:
        if m["expected_decision"] == "ALLOW" and not m.get("known_false_negative"):
            for p in (SRC / m["name"]).rglob("*.py"):
                for marker in build_all.PAYLOAD_MARKERS:
                    assert marker not in p.read_text(), (p, marker)


def test_time_bomb_trigger_is_about_180_days_out():
    import re
    import time
    dist = config.ROOT / "packages" / "dist"
    tf = tarfile.open(next(dist.glob("timekeeper-sync-*.tar.gz")))
    setup = tf.extractfile("timekeeper-sync-1.0.0/setup.py").read().decode()
    trig = int(re.search(r"TRIGGER_EPOCH = (\d+)", setup).group(1))
    assert 179 * 86400 < trig - time.time() < 181 * 86400


def test_build_guard_rejects_marker_in_benign_and_foreign_urls():
    ok = {"name": "x", "description": "SIMULATED", "expected_decision": "ALLOW"}
    with pytest.raises(build_all.BuildError):
        build_all.check(ok, {"a.py": build_all.HEADER + "\nimport urllib.request\n"})
    bad = {"name": "x", "description": "SIMULATED", "expected_decision": "BLOCK"}
    with pytest.raises(build_all.BuildError):
        build_all.check(bad, {"a.py": build_all.HEADER + "\nU='http://evil.example/x'\n"})
    with pytest.raises(build_all.BuildError):
        build_all.check(bad, {"a.py": "print(1)\n"})
