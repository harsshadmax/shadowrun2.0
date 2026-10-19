"""Build the two benign calibration packages (host build of OUR benign code only) and capture
real pip traces for them in the analysis sandbox. Never use this for the malicious fixtures."""
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from shadowrun import canary, config, sandbox

ROOT = config.ROOT
FIX = ROOT / "tests" / "fixtures"
CASES = [("tinyjson-utils", "1.0.0", "wheel", "pip_wheel"), ("csvtoolkit", "1.0.0", "sdist", "pip_sdist")]


def build(name, kind, outdir):
    src = ROOT / "packages" / "src" / name
    flag = "--wheel" if kind == "wheel" else "--sdist"
    subprocess.check_call([sys.executable, "-m", "build", "--no-isolation", flag, "--outdir", str(outdir), str(src)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return next(outdir.iterdir())


def main():
    FIX.mkdir(parents=True, exist_ok=True)
    for name, ver, kind, label in CASES:
        with tempfile.TemporaryDirectory() as td:
            f = build(name, kind, Path(td))
            sha = hashlib.sha256(f.read_bytes()).hexdigest()
            cache = config.FETCH_DIR / sha
            cache.mkdir(parents=True, exist_ok=True)
            shutil.copy(f, cache / f.name)
        cs = canary.create_home("calib-" + label)
        out = config.TRACE_DIR / ("calib-" + label)
        shutil.rmtree(out, ignore_errors=True)
        try:
            r = sandbox.run_container(sandbox.install_command(name, ver, sha), analysis=True, home=cs.home,
                                      out_dir=out, cache_dir=cache)
            print(label, "exit", r.exit_code, "timeout", r.timed_out, r.logs.strip()[-300:])
            shutil.copy(out / "trace.log", FIX / f"{label}.trace.log")
        finally:
            canary.cleanup_home(cs)


main()
