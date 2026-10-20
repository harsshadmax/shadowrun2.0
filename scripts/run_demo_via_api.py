"""Run the documented safe demo against the running dashboard server, using only its public API, so the doctor
check, the run ids and the timestamps all come from the same server process:
  1. fresh doctor check   2. unguarded install (the left half)   3. simulated agent through the gate (the right half)"""
import json
import sys
import time
import urllib.request
from pathlib import Path

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
TOKEN = (Path(__file__).resolve().parent.parent / ".data" / "demo_token").read_text().strip()


def call(path, method="GET", body=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Demo-Token": TOKEN, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


call("/api/v1/admin/demo-reset", "POST", {})
d = call("/api/v1/doctor/refresh", "POST", {})
print(f"1. doctor refreshed: {d['state']} check #{d['id']} finished {d['finished_at'][11:19]} UTC")
u = call("/api/v1/demo/unguarded", "POST", {"spec": "report-export-pro"})
print(f"2. unguarded install (no gate): leaked canary tokens reaching the sink = {len(u['leaked_tokens'])} {u['leaked_tokens']}")
base = (call("/api/v1/agent/events?since_id=0")["events"] or [{"id": 0}])[-1]["id"]
call("/api/v1/agent/run", "POST", {})
seen = base
print("3. simulated agent through the gate:")
for _ in range(120):
    time.sleep(1)
    out = call(f"/api/v1/agent/events?since_id={seen}")
    for ev in out["events"]:
        seen = ev["id"]
        print(f"   {ev['kind']:<15} {ev['message'][:150]}")
    if not out["running"] and seen > base:
        break
