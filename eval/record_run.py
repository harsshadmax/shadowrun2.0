"""Record one full demo run (unguarded leak, gated verdict, agent transcript) as a backup for stage use.
Writes eval/results/recorded_run.json and recorded_run.md. Needs the sandbox services (`shadowrun up`)."""
import json
import sys
import time
from datetime import datetime, timezone

from agent.scripted_agent import AGENT_ID, TASK, run_task
from shadowrun import config, db, pipeline

OUT = config.ROOT / "eval" / "results"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    db.init_db()
    pipeline.ensure_doctor(force=True)
    t0 = time.time()
    unguarded = pipeline.run_exposed("report-export-pro", agent_id="demo-unguarded")
    events: list[dict] = []
    gated: dict[str, dict] = {}

    def act(spec):
        res = pipeline.summarize(pipeline.run_action(spec, agent_id=AGENT_ID))
        gated[spec] = res
        return res

    def log(kind, message, run_id=None):
        db.add_agent_event(AGENT_ID, run_id, kind, message)
        events.append({"kind": kind, "message": message, "run_id": run_id})

    outcome = run_task(act, log, workdir=config.DATA / "agent_workspace")
    rec = {
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": "SIMULATED scenario: simulated agent, simulated package, fake secrets, sink inside the sandbox network.",
        "task": TASK, "duration_s": round(time.time() - t0, 1),
        "without_shadowrun": {"leaked_tokens": unguarded["leaked_tokens"],
                              "sink_events": [{"method": e["method"], "path": e["path"], "body": e["body"][:300]}
                                              for e in unguarded["sink_events"]]},
        "with_shadowrun": {spec: {k: r[k] for k in ("decision", "label", "reason", "matched_rules", "findings",
                                                     "decision_ms", "phases", "sha256")} for spec, r in gated.items()},
        "agent_transcript": events, "outcome": outcome,
    }
    (OUT / "recorded_run.json").write_text(json.dumps(rec, indent=2))
    md = [f"# Recorded demo run ({rec['recorded_at']})", "", f"_{rec['note']}_", "", f"Task: **{TASK}**", "",
          "## Without Shadow-Run", "", f"Leaked canary tokens reaching the sink: **{len(unguarded['leaked_tokens'])}** "
          f"({', '.join(unguarded['leaked_tokens'])})", "", "## With Shadow-Run", ""]
    for spec, r in gated.items():
        md.append(f"- `{spec}`: **{r['decision']}** in {r['decision_ms'] / 1000:.1f}s. {r['reason']}")
        for f in r["findings"]:
            md.append(f"  - {f['severity']} {f['rule_id']}: {f['message']}")
    md += ["", "## Agent transcript (SIMULATED AGENT)", ""]
    md += [f"{i}. `{e['kind']}` {e['message']}" for i, e in enumerate(events, 1)]
    (OUT / "recorded_run.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    sys.exit(main())
