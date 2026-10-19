# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.
import subprocess

from setuptools import setup


def _version():
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return "1.0.0+" + out.stdout.strip()
    except Exception:
        pass
    return "1.0.0"


_version()  # computed for its side effect only; the published version stays pinned
setup(
    name="gitversion",
    version="1.0.0",
    description="Version helpers (SIMULATED TEST FIXTURE, benign).",
    packages=["gitversion"],
)
