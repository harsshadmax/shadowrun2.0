"""Single source of truth for sandbox health (replaces the separate pipeline and dashboard doctor caches).

Rules that keep the displayed status honest:
  * one status object, produced under the same RLock that serialises scans, so a doctor check can never run
    concurrently with a scan and never share state with one;
  * every status has an id and a finish time; each run records the id of the check that gated it;
  * a status older than TTL_S is reported STALE, a missing one UNKNOWN, never PASS;
  * `ok` is always recomputed from the individual checks, never trusted from a caller;
  * an anomaly during a run (untrusted evidence, sandbox error) invalidates the status so the next run re-checks.
"""
import json
import threading
import time
import uuid
from dataclasses import dataclass, field

from . import db

TTL_S = 120
# One lock for every use of the sandbox: scans, baselines, doctor, benchmark. Re-entrant so a scan can
# refresh the doctor from inside its own critical section.
RUN_LOCK = threading.RLock()
_state_lock = threading.Lock()
_latest: "DoctorStatus | None" = None
_invalidated: str | None = None


class DoctorFailed(Exception):
    pass


@dataclass(frozen=True)
class DoctorStatus:
    id: str
    started_at: str
    finished_at: str
    finished_epoch: float
    checks: tuple = field(default_factory=tuple)

    @property
    def ok(self) -> bool:  # recomputed, never stored
        return bool(self.checks) and all(c.get("ok") is True for c in self.checks)


def _view(status: "DoctorStatus | None", now: float, invalidated: str | None) -> dict:
    if status is None:
        return {"state": "UNKNOWN", "id": None, "finished_at": None, "age_s": None, "checks": [],
                "detail": "no doctor check has run in this process yet"}
    age = max(0.0, now - status.finished_epoch)
    if not status.ok:
        state, detail = "FAIL", "; ".join(f"{c['n']}. {c['name']}" for c in status.checks if not c.get("ok"))
    elif invalidated:
        state, detail = "STALE", f"invalidated: {invalidated}"
    elif age > TTL_S:
        state, detail = "STALE", f"last check is {int(age)}s old (limit {TTL_S}s)"
    else:
        state, detail = "PASS", ""
    return {"state": state, "id": status.id, "finished_at": status.finished_at, "age_s": round(age, 1),
            "checks": list(status.checks), "detail": detail}


def peek(now: float | None = None) -> dict:
    """Current status without running anything. Safe to call from the dashboard at any time."""
    with _state_lock:
        return _view(_latest, time.time() if now is None else now, _invalidated)


def busy() -> bool:
    """True when another thread is inside a scan or a doctor check."""
    if RUN_LOCK.acquire(blocking=False):
        RUN_LOCK.release()
        return False
    return True


def refresh(reason: str = "") -> DoctorStatus:
    """Run the doctor checks now (serialised with scans) and publish the result."""
    from . import doctor  # looked up at call time so tests can substitute run_checks
    global _latest, _invalidated
    with RUN_LOCK:
        started = db.now_iso()
        checks = tuple(doctor.run_checks())
        status = DoctorStatus(id=uuid.uuid4().hex[:10], started_at=started, finished_at=db.now_iso(),
                              finished_epoch=time.time(), checks=checks)
        with _state_lock:
            _latest, _invalidated = status, None
        try:
            db.init_db()
            db.insert_doctor_run(status.id, status.started_at, status.finished_at, status.ok,
                                 json.dumps(list(checks)), reason)
        except Exception:
            pass  # persistence is for correlation; the in-memory status still gates runs
        return status


def ensure_pass(force: bool = False) -> DoctorStatus:
    """Gate for every run: a fresh PASS, or refresh. Raises DoctorFailed unless the result is PASS."""
    with RUN_LOCK:
        with _state_lock:
            usable = _latest if (not force and _latest is not None) else None
            view = _view(usable, time.time(), _invalidated)
        if usable is None or view["state"] != "PASS":
            usable = refresh("gate" if not force else "forced")
        if not usable.ok:
            raise DoctorFailed("doctor failed: sandbox cannot be trusted. Run `shadowrun doctor`.")
        return usable


def invalidate(reason: str) -> None:
    """Mark the latest status as no longer trustworthy (the next gate re-runs the doctor)."""
    global _invalidated
    with _state_lock:
        _invalidated = reason


def reset_for_tests() -> None:
    global _latest, _invalidated
    with _state_lock:
        _latest, _invalidated = None, None


def correlate(run_report: dict, current: dict) -> dict:
    """Describe how a run's doctor check relates to the current status, so the UI never merges them silently."""
    at_run = run_report.get("doctor") or {}
    if not at_run.get("id"):
        return {"consistent": False, "label": "UNKNOWN", "note": "this run has no recorded doctor check"}
    if current["state"] in ("PASS",) and current["id"] == at_run["id"]:
        return {"consistent": True, "label": "PASS", "note": "same check as the current status"}
    if current["state"] in ("FAIL", "STALE", "UNKNOWN"):
        return {"consistent": False, "label": current["state"],
                "note": f"sandbox health now: {current['state']}; this verdict used check {at_run['id']}"}
    return {"consistent": False, "label": "PASS", "note": f"gated by check {at_run['id']} (a newer check passed since)"}
