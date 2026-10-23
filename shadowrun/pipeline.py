"""pip install <spec> pipeline (blueprint 2.2). Any error ends in a non-ALLOW outcome (fail closed)."""
import hashlib
import json
import re
import time
import uuid
from pathlib import Path

from . import audit, canary, config, db, detector, fetcher, health, monitor, policy, sandbox
from .models import Finding

DoctorFailed = health.DoctorFailed


def ensure_doctor(force: bool = False) -> health.DoctorStatus:
    """Refuse to run unless the sandbox self-test passes. Uses the single shared health status."""
    return health.ensure_pass(force)


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


def summarize(run: dict) -> dict:
    """JSON-safe public view of a run (no pydantic objects, no raw traces)."""
    d = run.get("decision_obj")
    report = {}
    try:
        report = json.loads(run.get("report_json") or "{}")
    except Exception:
        pass
    return {
        "run_id": run["id"], "spec": run.get("spec"), "package": run.get("package_name"),
        "version": run.get("package_version"), "sha256": run.get("sha256"), "setup": run.get("setup"),
        "decision": run.get("decision"), "label": d.label if d else None,
        "indeterminate": d.indeterminate if d else False,
        "reason": run.get("decision_reason"), "matched_rules": d.matched_rules if d else [],
        "confidence": "limited", "findings": run.get("findings", []),
        "decision_ms": run.get("decision_ms"), "phases": json.loads(run.get("phase_ms_json") or "{}"),
        "state": run.get("state"), "error": run.get("error"), "doctor": report.get("doctor"),
    }


def run_exposed(spec: str, agent_id: str = "demo", setup: str = "no_guard", emit=None,
                scenario_id: str | None = None, run_id: str | None = None) -> dict:
    """Baseline / unguarded half of the demo: install in an `exposed` container (no strace, no analysis).
    Leaks are measured only by canary tokens reaching the sink."""
    with health.RUN_LOCK:
        return _run_exposed(spec, agent_id, setup, emit, scenario_id, run_id)


def _run_exposed(spec, agent_id, setup, emit, scenario_id, run_id) -> dict:
    emit = emit or (lambda kind, data: None)
    run_id = run_id or uuid.uuid4().hex[:12]
    db.init_db()
    db.insert_run(run_id, agent_id=agent_id, package_name=spec, setup=setup, state="RECEIVED", scenario_id=scenario_id)
    cs = None
    error = None
    leaked: list[str] = []
    sink_events: list[dict] = []
    try:
        status = ensure_doctor()  # same isolation guarantees apply to the exposed container
        fetched = fetcher.fetch(spec)
        db.update_run(run_id, package_name=fetched.name, package_version=fetched.version, sha256=fetched.sha256)
        cs = canary.create_home(run_id)
        sink_off = _sink_size()
        emit("phase", {"phase": "install", "state": "start"})
        res = sandbox.run_container(sandbox.install_command(fetched.name, fetched.version, fetched.sha256),
                                    home=cs.home, cache_dir=Path(fetched.cache_dir))
        time.sleep(0.3)
        sink_events = _sink_events(sink_off, res.container_ip)
        needle = f"CANARY-{cs.run_token}-"
        blob = json.dumps(sink_events, default=str)
        leaked = sorted(set(re.findall(rf"{re.escape(needle)}\w+", blob)))
        db.update_run(run_id, container_ip=res.container_ip, state="DECIDED", decision="NONE",
                      decision_reason=f"{setup}: install completed unguarded; {len(leaked)} canary token(s) leaked",
                      report_json=json.dumps({"exit_code": res.exit_code, "leaked_tokens": leaked,
                                              "doctor": {"id": status.id, "checked_at": status.finished_at,
                                                         "ok": status.ok}}))
        emit("phase", {"phase": "install", "state": "done"})
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
        db.update_run(run_id, state="ERROR", decision_reason=error)
    finally:
        if cs is not None:
            canary.cleanup_home(cs)
    return {"run_id": run_id, "setup": setup, "leaked_tokens": leaked, "sink_events": sink_events, "error": error}


def run_action(spec: str, agent_id: str = "cli", setup: str = "shadowrun", pin_sha256: str | None = None,
               emit=None, scenario_id: str | None = None, run_id: str | None = None) -> dict:
    """Fetch, hash, analyze in the sandbox, record, decide. Returns the run dict."""
    with health.RUN_LOCK:  # a doctor check can never interleave with a scan
        return _run_action(spec, agent_id, setup, pin_sha256, emit, scenario_id, run_id)


def _save_trace(run_id: str, text: str) -> None:
    """Keep a host-side copy of the verified trace as evidence (written by the host, not the sandbox)."""
    d = config.TRACE_DIR / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "trace.log").write_text(text)


def _run_action(spec, agent_id, setup, pin_sha256, emit, scenario_id, run_id) -> dict:
    emit = emit or (lambda kind, data: None)
    t_recv = time.perf_counter()
    run_id = run_id or uuid.uuid4().hex[:12]
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
    evidence_ok = True
    try:
        t_gate = time.perf_counter()
        status = ensure_doctor()  # near zero while the shared status is a fresh PASS; a full check otherwise
        phases["gate_ms"] = (time.perf_counter() - t_gate) * 1000
        doctor_ref = {"id": status.id, "checked_at": status.finished_at, "ok": status.ok}
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
        pin = pin_sha256 or fetched.sha256
        sink_off = _sink_size()
        emit("phase", {"phase": "sandbox", "state": "start"})
        audit.append("SANDBOX_STARTED", run_id, {"pin_sha256": pin, "design": "package container + tracer sidecar",
                                                 "doctor_id": status.id, "doctor_checked_at": status.finished_at})
        t = time.perf_counter()
        install_cmd = sandbox.install_command(fetched.name, fetched.version, pin)
        res, ev = sandbox.run_analysis(install_cmd, home=cs.home, cache_dir=Path(fetched.cache_dir))
        phases["sandbox_ms"] = (time.perf_counter() - t) * 1000
        phases.update({f"sandbox_{k}": v for k, v in res.phases.items()})  # where the sandbox time went
        db.update_run(run_id, container_ip=res.container_ip, state="ANALYZING")
        audit.append("SANDBOX_FINISHED", run_id, {"exit_code": res.exit_code, "timed_out": res.timed_out,
                                                  "container_ip": res.container_ip, "trace_sha256": ev.sha256,
                                                  "trace_bytes": ev.size, "evidence_trusted": ev.trusted})
        emit("phase", {"phase": "sandbox", "state": "done", "ms": phases["sandbox_ms"]})

        emit("phase", {"phase": "analyze", "state": "start"})
        t = time.perf_counter()
        time.sleep(0.3)  # let the sink flush
        if ev.trace_text:
            _save_trace(run_id, ev.trace_text)
        pr = monitor.parse_trace(ev.trace_text, final_exec=sandbox.FINAL_EXEC)
        problems = pr.completeness_problems()
        if ev.strace_rc is None and ev.done:
            problems.append("tracer exit status missing")
        evidence_ok = ev.trusted and not problems
        ctx = detector.RunContext(
            canary_paths=list(cs.canary_paths.values()), run_token=cs.run_token,
            sink_events=_sink_events(sink_off, res.container_ip),
            hash_mismatch=hash_mismatch_in(res.logs),
            install_failed=res.exit_code not in (0, None), timed_out=res.timed_out,
            evidence_errors=list(ev.errors), evidence_tampered=list(ev.tampered),
            trace_problems=problems, require_pip_exec=True, wrapper_cmd=install_cmd, init_pid=pr.final_exec_pid)
        findings = detector.analyze(pr.events, ctx)
        phases["analyze_ms"] = (time.perf_counter() - t) * 1000
        report = {"parse_warnings": pr.parse_warnings, "events": len(pr.events), "exit_code": res.exit_code,
                  "pip_log_tail": res.logs[-600:], "trace_lines": pr.lines, "trace_problems": problems,
                  "evidence": {"trusted": ev.trusted, "sha256": ev.sha256, "bytes": ev.size,
                               "errors": ev.errors, "tampered": ev.tampered},
                  "doctor": doctor_ref}
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
        evidence_ok = False
        db.update_run(run_id, state="ERROR", phase_ms_json=json.dumps(phases))
    finally:
        if cs is not None:
            canary.cleanup_home(cs)  # traces under .data/trace/<run> are kept as evidence
        if not evidence_ok:  # anything odd about isolation or evidence: do not trust the cached health status
            health.invalidate(f"run {run_id}: evidence or sandbox anomaly")

    t = time.perf_counter()
    decision = policy.decide_error(error, block=block_on_error) if error else policy.decide(findings)
    phases["decide_ms"] = (time.perf_counter() - t) * 1000
    decision_ms = (time.perf_counter() - t_recv) * 1000  # receive-to-decision
    db.update_run(run_id, state="DECIDED", decision=decision.decision, decision_reason=decision.reason,
                  decision_ms=decision_ms, phase_ms_json=json.dumps(phases))
    audit.append("DECISION_MADE", run_id, {"decision": decision.decision, "matched_rules": decision.matched_rules,
                                           "decision_ms": round(decision_ms, 1), "error": error,
                                           "indeterminate": decision.indeterminate})
    emit("decision", {"decision": decision.decision, "reason": decision.reason, "indeterminate": decision.indeterminate,
                      "matched_rules": decision.matched_rules, "decision_ms": decision_ms})
    run = db.get_run(run_id)
    run["spec"] = spec
    run["error"] = error
    run["decision_obj"] = decision
    run["elapsed_ms"] = decision_ms
    return run
