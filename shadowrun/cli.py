import argparse
import json
import subprocess
import sys

from . import config

ICON = {"ALLOW": "ALLOWED", "BLOCK": "BLOCKED", "ESCALATE": "NEEDS HUMAN REVIEW (denied)"}


def _pip_install(args) -> int:
    from . import pipeline
    run = pipeline.run_action(args.spec, agent_id="cli", pin_sha256=args.pin)
    out = pipeline.summarize(run)
    if args.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        sha = (out["sha256"] or "")[:12]
        print(f"shadowrun: {out['package'] or args.spec}=={out['version'] or '?'}  sha256:{sha}")
        ms = out["decision_ms"] or 0
        print(f"{ICON[out['decision']]}  (decision in {ms / 1000:.1f}s)")
        for f in out["findings"]:
            print(f"  {f['severity']:<8} {f['rule_id']:<22} {f['message']}")
        print(f"Reason: {out['reason']}")
        if out["matched_rules"]:
            print(f"Matched policy rules: {', '.join(out['matched_rules'])}")
        print("Confidence: limited. This reduces risk; it does not prove safety.")
    return run["decision_obj"].exit_code


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="shadowrun", description="Behavioural verification gate for package installs")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("doctor", "up", "down", "reset"):
        sub.add_parser(name)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8000)
    pip = sub.add_parser("pip")
    pip_sub = pip.add_subparsers(dest="pip_cmd", required=True)
    inst = pip_sub.add_parser("install")
    inst.add_argument("spec")
    inst.add_argument("--pin", help="expected sha256 (otherwise the fetched hash is pinned)")
    inst.add_argument("--json", action="store_true")
    ev = sub.add_parser("eval")
    ev.add_argument("--repeats", type=int, default=3)
    au = sub.add_parser("audit")
    au_sub = au.add_subparsers(dest="audit_cmd", required=True)
    au_sub.add_parser("verify")
    args = p.parse_args(argv)

    if args.cmd == "doctor":
        from .doctor import run_doctor
        return 0 if run_doctor() else 1
    if args.cmd in ("up", "down"):
        return subprocess.call(["bash", str(config.ROOT / "scripts" / f"{args.cmd}.sh")])
    if args.cmd == "reset":
        from . import db
        db.init_db()
        db.demo_reset()
        print("demo reset: runs, findings, agent events and sink log cleared (audit log kept)")
        return 0
    if args.cmd == "serve":
        import uvicorn
        uvicorn.run("shadowrun.api:app", host="127.0.0.1", port=args.port, log_level="warning")
        return 0
    if args.cmd == "pip":
        return _pip_install(args)
    if args.cmd == "audit":
        from . import audit, db
        db.init_db()
        res = audit.verify()
        print(json.dumps(res))
        return 0 if res["ok"] else 1
    if args.cmd == "eval":
        try:
            from eval.run_eval import main as eval_main
        except ImportError:
            print("eval is not built yet (blueprint step 8)", file=sys.stderr)
            return 1
        return eval_main(args.repeats)
    return 1


if __name__ == "__main__":
    sys.exit(main())
