"""Bug 1: one shared, honest health status (PASS / FAIL / STALE / UNKNOWN), never merged across runs or freshness."""
import threading
import time

import pytest

from shadowrun import config, db, doctor, health


def checks(*oks):
    return [{"n": i + 1, "name": f"check {i + 1}", "ok": ok, "detail": ""} for i, ok in enumerate(oks)]


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "h.db")
    db.init_db()
    health.reset_for_tests()
    yield
    health.reset_for_tests()


@pytest.fixture
def fake_doctor(monkeypatch):
    state = {"result": checks(True, True, True), "calls": 0, "delay": 0.0, "log": []}

    def run_checks():
        state["calls"] += 1
        state["log"].append("doctor_start")
        time.sleep(state["delay"])
        return list(state["result"])
    monkeypatch.setattr(doctor, "run_checks", run_checks)
    return state


def test_unknown_before_any_check():
    v = health.peek()
    assert v["state"] == "UNKNOWN" and v["id"] is None and v["checks"] == []


def test_pass_after_refresh_with_id_and_time(fake_doctor):
    s = health.refresh("test")
    v = health.peek()
    assert v["state"] == "PASS" and v["id"] == s.id and v["finished_at"] and v["age_s"] < 5
    row = db.get_doctor_run(s.id)  # persisted so a run's report can be correlated later
    assert row["ok"] is True and len(row["checks"]) == 3 and row["reason"] == "test"


def test_status_becomes_stale_after_ttl_never_pass(fake_doctor):
    s = health.refresh()
    v = health.peek(now=s.finished_epoch + health.TTL_S + 1)
    assert v["state"] == "STALE" and "old" in v["detail"]
    assert health.peek(now=s.finished_epoch + health.TTL_S - 1)["state"] == "PASS"


def test_one_failed_check_is_fail_even_if_others_pass(fake_doctor):
    fake_doctor["result"] = checks(True, True, False, True)
    health.refresh()
    v = health.peek()
    assert v["state"] == "FAIL" and "3. check 3" in v["detail"]


def test_contradictory_or_malformed_results_never_read_as_pass(fake_doctor):
    for bad in ([], checks(True, "yes"), checks(1, True), [{"n": 1, "name": "x"}]):
        health.reset_for_tests()
        fake_doctor["result"] = bad
        health.refresh()
        assert health.peek()["state"] == "FAIL", bad


def test_ok_is_recomputed_not_trusted_from_the_caller():
    s = health.DoctorStatus("id", "t0", "t1", time.time(), tuple(checks(True, False)))
    assert s.ok is False


def test_invalidate_makes_status_stale_and_next_gate_rechecks(fake_doctor):
    health.ensure_pass()
    assert fake_doctor["calls"] == 1
    health.ensure_pass()
    assert fake_doctor["calls"] == 1  # fresh PASS is reused
    health.invalidate("run x: evidence anomaly")
    assert health.peek()["state"] == "STALE" and "evidence anomaly" in health.peek()["detail"]
    health.ensure_pass()
    assert fake_doctor["calls"] == 2 and health.peek()["state"] == "PASS"


def test_failed_check_blocks_the_gate_and_stays_failed(fake_doctor):
    fake_doctor["result"] = checks(True, False)
    with pytest.raises(health.DoctorFailed):
        health.ensure_pass()
    with pytest.raises(health.DoctorFailed):  # not served from a cache
        health.ensure_pass()
    assert fake_doctor["calls"] == 2
    fake_doctor["result"] = checks(True, True)
    assert health.ensure_pass().ok


def test_force_always_rechecks(fake_doctor):
    health.ensure_pass()
    health.ensure_pass(force=True)
    assert fake_doctor["calls"] == 2


def test_every_run_status_gets_a_new_id(fake_doctor):
    a, b = health.refresh(), health.refresh()
    assert a.id != b.id and health.peek()["id"] == b.id


def test_concurrent_gates_run_the_doctor_once(fake_doctor):
    fake_doctor["delay"] = 0.15
    ids, errors = [], []

    def gate():
        try:
            ids.append(health.ensure_pass().id)
        except Exception as e:  # pragma: no cover
            errors.append(e)
    threads = [threading.Thread(target=gate) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors and fake_doctor["calls"] == 1 and len(set(ids)) == 1


def test_doctor_never_runs_concurrently_with_a_scan(fake_doctor):
    """The dashboard's check used to be able to overlap a scan. Now both need the same lock."""
    events = fake_doctor["log"]

    def scan():
        with health.RUN_LOCK:
            events.append("scan_start")
            time.sleep(0.3)
            events.append("scan_end")
    t = threading.Thread(target=scan)
    t.start()
    time.sleep(0.05)
    assert health.busy() is True
    health.refresh()  # blocks until the scan releases the lock
    t.join()
    assert events == ["scan_start", "scan_end", "doctor_start"]


def test_busy_reflects_other_threads_only():
    assert health.busy() is False
    with health.RUN_LOCK:
        assert health.busy() is False  # re-entrant: the owner is not "busy"
        seen = []
        t = threading.Thread(target=lambda: seen.append(health.busy()))
        t.start()
        t.join()
        assert seen == [True]


def test_correlate_run_to_current_status():
    run = {"doctor": {"id": "abc", "ok": True}}
    assert health.correlate(run, {"state": "PASS", "id": "abc"})["consistent"] is True
    newer = health.correlate(run, {"state": "PASS", "id": "zzz"})
    assert newer["consistent"] is False and "abc" in newer["note"]
    for state in ("FAIL", "STALE", "UNKNOWN"):
        c = health.correlate(run, {"state": state, "id": "zzz"})
        assert c["consistent"] is False and c["label"] == state
    assert health.correlate({}, {"state": "PASS", "id": "abc"})["label"] == "UNKNOWN"
    assert health.correlate({"doctor": {}}, {"state": "PASS", "id": "abc"})["consistent"] is False
