"""pip install <spec> pipeline (blueprint 2.2). Any error ends in a non-ALLOW outcome (fail closed)."""
import json
import threading
import time
import uuid
from pathlib import Path

from . import audit, canary, config, db, detector, fetcher, monitor, policy, sandbox
from .models import Finding

_doctor_lock = threading.Lock()
_doctor_ok_until = 0.0
DOCTOR_TTL_S = 300


class DoctorFailed(Exception):
    pass


def ensure_doctor(force: bool = False) -> None:
    """Refuse to run unless the sandbox self-test passes (cached for a few minutes)."""
    global _doctor_ok_until
    with _doctor_lock:
        if not force and time.time() < _doctor_ok_until:
            return
        from .doctor import run_doctor
        if not run_doctor(verbose=False):
            _doctor_ok_until = 0.0
            raise DoctorFailed("doctor failed: sandbox cannot be trusted. Run `shadowrun doctor`.")
        _doctor_ok_until = time.time() + DOCTOR_TTL_S


def _sink_events(offset: int, container_ip: str | None) -> list[dict]:
    if not config.SINK_LOG.exists():
        return []
    with open(config.SINK_LOG, "rb") as f:
        f.seek(offset)
        raw = f.read().decode("utf-8", errors="replace")
    out = []
    for line in raw.splitlines():
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if container_ip and ev.get("source_ip") == container_ip:
            out.append(ev)
    return out


def _sink_size() -> int:
    return config.SINK_LOG.stat().st_size if config.SINK_LOG.exists() else 0


def hash_mismatch_in(logs: str) -> bool:
    return "do not match the hashes" in logs.lower()


def run_action(spec: str, agent_id: str = "cli", setup: str = "shadowrun", pin_sha256: str | None = None,
               emit=None, scenario_id: str | None = None) -> dict:
    """Fetch, hash, analyze in the sandbox, record. Returns the run dict (decision applied by the caller/policy)."""
    emit = emit or (lambda kind, data: None)
    t_recv = time.perf_counter()
    run_id = uuid.uuid4().hex[:12]
    phases: dict = {}
    db.init_db()
    db.insert_run(run_id, agent_id=agent_id, package_name=spec, setup=setup, state="RECEIVED",
                  scenario_id=scenario_id)
    audit.append("ACTION_RECEIVED", run_id, {"spec": spec, "agent_id": agent_id, "setup": setup})
    findings: list[Finding] = []
    cs = None
    fetched = None
    error = None
    block_on_error = False
    try:
        ensure_doctor()
        emit("phase", {"phase": "fetch", "state": "start"})
        fetched = fetcher.fetch(spec)
        phases["fetch_ms"], phases["hash_ms"] = fetched.fetch_ms, fetched.hash_ms
        emit("phase", {"phase": "fetch", "state": "done", "ms": fetched.fetch_ms})
        emit("phase", {"phase": "hash", "state": "done", "ms": fetched.hash_ms, "sha256": fetched.sha256})
        db.update_run(run_id, package_name=fetched.name, package_version=fetched.version,
                      sha256=fetched.sha256, state="FETCHED")
        audit.append("FETCHED", run_id, {"name": fetched.name, "version": fetched.version,
                                         "file": fetched.filename, "sha256": fetched.sha256})

        cs = canary.create_home(run_id)
        out_dir = config.TRACE_DIR / run_id
        pin = pin_sha256 or fetched.sha256
        sink_off = _sink_size()
        emit("phase", {"phase": "sandbox", "state": "start"})
        audit.append("SANDBOX_STARTED", run_id, {"pin_sha256": pin, "seccomp": sandbox.seccomp_enabled()})
        t = time.perf_counter()
        res = sandbox.run_container(
            sandbox.install_command(fetched.name, fetched.version, pin), analysis=True, home=cs.home,
            out_dir=out_dir, cache_dir=Path(fetched.cache_dir))
        phases["sandbox_ms"] = (time.perf_counter() - t) * 1000
        db.update_run(run_id, container_ip=res.container_ip, state="ANALYZING")
        audit.append("SANDBOX_FINISHED", run_id, {"exit_code": res.exit_code, "timed_out": res.timed_out,
                                                  "container_ip": res.container_ip})
        emit("phase", {"phase": "sandbox", "state": "done", "ms": phases["sandbox_ms"]})

        emit("phase", {"phase": "analyze", "state": "start"})
        t = time.perf_counter()
        time.sleep(0.3)  # let the sink flush
        trace_file = out_dir / "trace.log"
        trace_text = trace_file.read_text(errors="replace") if trace_file.exists() else ""
        pr = monitor.parse_trace(trace_text)
        ctx = detector.RunContext(
            canary_paths=list(cs.canary_paths.values()), run_token=cs.run_token,
            sink_events=_sink_events(sink_off, res.container_ip),
            hash_mismatch=hash_mismatch_in(res.logs),
            install_failed=res.exit_code not in (0, None), timed_out=res.timed_out)
        findings = detector.analyze(pr.events, ctx)
        phases["analyze_ms"] = (time.perf_counter() - t) * 1000
        report = {"parse_warnings": pr.parse_warnings, "events": len(pr.events), "exit_code": res.exit_code,
                  "pip_log_tail": res.logs[-600:], "trace_empty": not trace_text}
        if not trace_text and not ctx.hash_mismatch:
            # no evidence at all: cannot vouch for this run
            findings.append(Finding(rule_id="INSTALL_FAILED", severity="medium",
                                    message="No strace output captured; run cannot be trusted",
                                    evidence={"exit_code": res.exit_code}))
        emit("phase", {"phase": "analyze", "state": "done", "ms": phases["analyze_ms"]})
        for f in findings:
            emit("finding", f.model_dump())
        db.add_findings(run_id, findings)
        audit.append("FINDINGS_RECORDED", run_id, {"count": len(findings), "rules": [f.rule_id for f in findings]})
        db.update_run(run_id, state="ANALYZED", report_json=json.dumps(report),
                      phase_ms_json=json.dumps(phases))
    except Exception as e:  # fail closed: an error never yields ALLOW
        error = f"{type(e).__name__}: {e}"
        block_on_error = isinstance(e, DoctorFailed)
        db.update_run(run_id, state="ERROR", phase_ms_json=json.dumps(phases))
    finally:
        if cs is not None:
            canary.cleanup_home(cs)  # traces under .data/trace/<run> are kept as evidence

    t = time.perf_counter()
    decision = policy.decide_error(error, block=block_on_error) if error else policy.decide(findings)
    phases["decide_ms"] = (time.perf_counter() - t) * 1000
    decision_ms = (time.perf_counter() - t_recv) * 1000  # receive-to-decision
    db.update_run(run_id, state="DECIDED", decision=decision.decision, decision_reason=decision.reason,
                  decision_ms=decision_ms, phase_ms_json=json.dumps(phases))
    audit.append("DECISION_MADE", run_id, {"decision": decision.decision, "matched_rules": decision.matched_rules,
                                           "decision_ms": round(decision_ms, 1), "error": error})
    emit("decision", {"decision": decision.decision, "reason": decision.reason,
                      "matched_rules": decision.matched_rules, "decision_ms": decision_ms})
    run = db.get_run(run_id)
    run["error"] = error
    run["decision_obj"] = decision
    run["elapsed_ms"] = decision_ms
    return run
