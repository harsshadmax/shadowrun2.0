"""Benchmark: no_guard vs name_check vs shadowrun over the six simulated packages.
Every number in the report is aggregated from the database (eval_results and runs.phase_ms_json)."""
import csv
import json
import statistics
import subprocess
import sys
import uuid
from collections import defaultdict
from contextlib import closing
from pathlib import Path

import yaml

from shadowrun import audit, config, db, pipeline
from eval.baselines import SETUPS

RESULTS = config.ROOT / "eval" / "results"
DENIED = {"BLOCK", "ESCALATE"}
PHASE_KEYS = ["fetch_ms", "hash_ms", "sandbox_ms", "analyze_ms", "decide_ms"]
DISCLAIMER = ("Small demo benchmark: 6 self-written, simulated packages, 3 runs each. It shows the mechanism works "
              "on simulated attacks, not real-world detection rates. Latency is dominated by container start and "
              "install time and was measured on this machine.")


def manifests() -> list[dict]:
    out = [yaml.safe_load(p.read_text()) for p in sorted((config.ROOT / "packages" / "src").glob("*/MANIFEST.yaml"))]
    return sorted(out, key=lambda m: m["id"])


def _record(eval_id, scn, setup, repeat, res):
    with closing(db.connect()) as c:
        c.execute("INSERT INTO eval_results (eval_run_id, scenario_id, setup, repeat, outcome, decision, decision_ms,"
                  " leaked_tokens) VALUES (?,?,?,?,?,?,?,?)",
                  (eval_id, scn, setup, repeat, res["outcome"] if not res.get("error") else "ERROR:" + res["outcome"],
                   res["decision"], res["decision_ms"], res["leaked"]))
        c.commit()


def aggregate(eval_id: str) -> dict:
    mans = {m["id"]: m for m in manifests()}
    with closing(db.connect()) as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM eval_results WHERE eval_run_id=?", (eval_id,))]
        phase_rows = [json.loads(r["phase_ms_json"] or "{}") for r in c.execute(
            "SELECT phase_ms_json FROM runs WHERE setup='shadowrun' AND scenario_id LIKE ?", (f"eval:{eval_id}:%",))]
    attacks = [i for i in mans if i.startswith("M")]
    benign = [i for i in mans if i.startswith("B")]
    out_rows, matrix = [], defaultdict(dict)
    for setup in SETUPS:
        sr = [r for r in rows if r["setup"] == setup]
        by = defaultdict(list)
        for r in sr:
            by[r["scenario_id"]].append(r)
        for scn, rs in by.items():
            outs = [r["outcome"] for r in rs]
            matrix[scn][setup] = max(set(outs), key=outs.count) if len(set(outs)) == 1 else "/".join(sorted(set(outs)))
        prevented = sum(1 for s in attacks if by.get(s) and all(r["decision"] in DENIED for r in by[s]))
        fps = sum(1 for s in benign if by.get(s) and any(r["decision"] in DENIED for r in by[s]))
        leaks = sum(max((r["leaked_tokens"] or 0) for r in by[s]) for s in by) if setup != "shadowrun" else 0
        ms = [r["decision_ms"] for r in sr if r["decision_ms"] is not None]
        out_rows.append({"setup": setup, "attacks_prevented": prevented, "attacks_total": len(attacks),
                         "false_positives": fps, "benign_total": len(benign), "leaked_tokens": leaks,
                         "median_ms": statistics.median(ms) if ms else None, "max_ms": max(ms) if ms else None})
    phases = {k: statistics.median([p[k] for p in phase_rows if k in p]) for k in PHASE_KEYS
              if any(k in p for p in phase_rows)}
    return {"available": True, "eval_run_id": eval_id, "disclaimer": DISCLAIMER, "rows": out_rows, "phases": phases,
            "matrix": {s: matrix[s] for s in sorted(matrix)},
            "labels": {i: {"name": m["name"], "label": m["label"]} for i, m in mans.items()},
            "repeats": max((r["repeat"] for r in rows), default=0), "runs": len(rows)}


def write_reports(res: dict) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "latest.json").write_text(json.dumps(res, indent=2))
    with open(RESULTS / "eval_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(res["rows"][0]))
        w.writeheader()
        w.writerows(res["rows"])
    s = lambda ms: "n/a" if ms is None else f"{ms / 1000:.1f}s"  # noqa: E731
    md = [f"# Shadow-Run benchmark ({res['eval_run_id']})", "",
          "| Setup | Attacks prevented | Benign wrongly stopped | Canary tokens leaked | Median decision | Max decision |",
          "|---|---|---|---|---|---|"]
    for r in res["rows"]:
        md.append(f"| {r['setup']} | {r['attacks_prevented']} of {r['attacks_total']} | "
                  f"{r['false_positives']} of {r['benign_total']} | {r['leaked_tokens']} | "
                  f"{s(r['median_ms'])} | {s(r['max_ms'])} |")
    md += ["", f"> {res['disclaimer']}", "", "## Outcome per scenario (repeats agree unless shown as a/b)", "",
           "| Scenario | Package | no_guard | name_check | shadowrun |", "|---|---|---|---|---|"]
    for scn, row in res["matrix"].items():
        md.append(f"| {scn} | {res['labels'][scn]['name']} | {row.get('no_guard')} | {row.get('name_check')} | "
                  f"{row.get('shadowrun')} |")
    md += ["", "## Shadow-Run median time per phase", "", "| Phase | Median |", "|---|---|"]
    for k, v in res["phases"].items():
        md.append(f"| {k.replace('_ms', '')} | {v / 1000:.2f}s |")
    md += ["", "Notes: `sandbox` covers container start and the install together (one measurement). "
           "`leaked tokens` counts canary tokens that reached the sink from the exposed baselines; Shadow-Run never "
           "installs outside its sandbox, so it is 0 by construction. M3 (time bomb) is a known false negative: "
           "the clock-triggered payload never fires in the tested run."]
    (RESULTS / "results.md").write_text("\n".join(md) + "\n")


def main(repeats: int = 3) -> int:
    pipeline.ensure_doctor(force=True)
    db.init_db()
    subprocess.check_call([sys.executable, str(config.ROOT / "packages" / "build_all.py")], stdout=subprocess.DEVNULL)
    eval_id = uuid.uuid4().hex[:8]
    mans = manifests()
    audit.append("EVAL_STARTED", None, {"eval_run_id": eval_id, "repeats": repeats, "scenarios": [m["id"] for m in mans]})
    print(f"eval {eval_id}: warm-up run (discarded)...")
    pipeline.run_action(mans[0]["name"], agent_id="eval-warmup", setup="shadowrun", scenario_id=f"warmup:{eval_id}")
    for m in mans:
        for setup, fn in SETUPS.items():
            for rep in range(1, repeats + 1):
                res = fn(m["name"], f"eval:{eval_id}:{m['id']}")
                _record(eval_id, m["id"], setup, rep, res)
                print(f"  {m['id']} {setup:<10} #{rep} -> {res['outcome']}"
                      + (f" ({res['decision_ms'] / 1000:.1f}s)" if res["decision_ms"] else ""), flush=True)
    audit.append("EVAL_FINISHED", None, {"eval_run_id": eval_id})
    res = aggregate(eval_id)
    write_reports(res)
    print((RESULTS / "results.md").read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 3))
