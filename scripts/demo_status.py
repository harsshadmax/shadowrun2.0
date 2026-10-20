"""Print the live sandbox-health status and the latest verdicts straight from the running API, so the terminal
half of the demo and the dashboard half describe the same state (same doctor check id, same run ids, same times)."""
import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.loads(r.read())


doc = get("/api/v1/doctor")
print(f"doctor status   : {doc['state']}   check #{doc['id']}   finished {doc['finished_at'][11:19]} UTC   age {doc['age_s']:.0f}s")
for c in doc["checks"]:
    print(f"  {c['n']}. {'PASS' if c['ok'] is True else 'FAIL'}  {c['name']}")
print()
runs = [r for r in get("/api/v1/runs?limit=20")["runs"] if r["setup"] == "shadowrun"][:3]
print("latest verdicts (gate setup):")
for r in runs:
    d = get(f"/api/v1/runs/{r['id']}")
    rep = json.loads(d.get("report_json") or "{}")
    ref = rep.get("doctor") or {}
    ev = rep.get("evidence") or {}
    same = "same check as now" if ref.get("id") == doc["id"] else "gated by an earlier check"
    print(f"  run #{r['id']}  {r['package_name']:<18} {r['decision']:<8} {r['decision_ms'] / 1000:.1f}s   "
          f"gated by doctor #{ref.get('id')} @ {str(ref.get('checked_at'))[11:19]} ({same})   "
          f"trace trusted={ev.get('trusted')} sha256={str(ev.get('sha256'))[:12]}")
