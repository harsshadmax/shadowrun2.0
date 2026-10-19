"""Build the six simulated packages into packages/dist/ WITHOUT running any package code on the host
(sdists and wheels are assembled by hand; `python -m build` would execute setup.py).
Fails if a benign fixture contains payload markers or a fixture lacks the SIMULATED header."""
import hashlib
import re
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from shadowrun.sdist_tool import make_sdist, make_wheel  # noqa: E402

SRC = ROOT / "packages" / "src"
DIST = ROOT / "packages" / "dist"
HEADER = "# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX."
EXCLUDE = {"MANIFEST.yaml", "pyproject.toml"}
PAYLOAD_MARKERS = ["urllib.request", "sink:9000", ".ssh", ".aws", ".bashrc", "id_rsa", ".env", "socket", "os.system"]
TRIGGER_DAYS = 180


class BuildError(Exception):
    pass


def collect(src: Path, form: str) -> dict[str, str]:
    files = {}
    for p in sorted(src.rglob("*")):
        rel = p.relative_to(src).as_posix()
        if not p.is_file() or rel in EXCLUDE or "__pycache__" in rel or "/build/" in rel:
            continue
        if form == "wheel" and rel == "setup.py":
            continue
        files[rel] = p.read_text()
    return files


def check(manifest: dict, files: dict[str, str]) -> None:
    name = manifest["name"]
    if "SIMULATED" not in manifest["description"]:
        raise BuildError(f"{name}: manifest description must contain SIMULATED")
    if "simulated" in name.lower():
        raise BuildError(f"{name}: package names must be plausible (no 'SIMULATED' in the name)")
    for rel, text in files.items():
        if rel.endswith(".py") and not text.startswith(HEADER):
            raise BuildError(f"{name}/{rel}: missing SIMULATED header")
        for url in re.findall(r"https?://[^\s\"')]+", text):
            if not url.startswith("http://sink:9000/"):
                raise BuildError(f"{name}/{rel}: payload may only talk to sink, found {url}")
    if manifest["expected_decision"] == "ALLOW" and not manifest.get("known_false_negative"):
        for rel, text in files.items():
            for m in PAYLOAD_MARKERS:
                if m in text:
                    raise BuildError(f"benign fixture {name}/{rel} contains payload marker {m!r}")


def main() -> int:
    DIST.mkdir(parents=True, exist_ok=True)
    for f in DIST.iterdir():
        if f.name != ".gitkeep":
            f.unlink()
    rows = []
    for mpath in sorted(SRC.glob("*/MANIFEST.yaml")):
        manifest = yaml.safe_load(mpath.read_text())
        src = mpath.parent
        files = collect(src, manifest["form"])
        if "timekeeper" in manifest["name"]:
            trigger = int(time.time()) + TRIGGER_DAYS * 86400
            files = {k: v.replace("__TRIGGER_EPOCH__", str(trigger)) for k, v in files.items()}
        check(manifest, files)
        build = make_wheel if manifest["form"] == "wheel" else make_sdist
        out = build(manifest["name"], manifest["version"], files, DIST, manifest["description"])
        sha = hashlib.sha256(out.read_bytes()).hexdigest()
        rows.append((manifest, out.name, sha))
    lines = ["# Simulated package fixtures", "", "All SIMULATED, inert outside the Shadow-Run sandbox.", "",
             "| ID | Name | Version | Form | Expected | File | SHA-256 |", "|---|---|---|---|---|---|---|"]
    for m, fn, sha in sorted(rows, key=lambda r: r[0]["id"]):
        lines.append(f"| {m['id']} | {m['name']} | {m['version']} | {m['form']} | {m['expected_decision']} | {fn} | {sha[:12]} |")
    (DIST / "INDEX.md").write_text("\n".join(lines) + "\n")
    print(f"built {len(rows)} packages into {DIST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
