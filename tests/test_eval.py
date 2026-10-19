import pytest

from eval import baselines, run_eval
from shadowrun import config, db


def test_edit_distance():
    assert baselines.edit_distance("requests", "requests") == 0
    assert baselines.edit_distance("reqeusts", "requests") == 2
    assert baselines.edit_distance("kitten", "sitting") == 3


def test_name_check_catches_typosquat_but_not_fixtures_or_real_names():
    assert baselines.name_blocked("reqeusts")[0] is True
    assert baselines.name_blocked("requessts")[0] is True  # blocklist
    assert baselines.name_blocked("requests")[0] is False  # the real package
    for ok in ("tinyjson-utils", "csvtoolkit", "gitversion", "report-export-pro", "timekeeper-sync"):
        assert baselines.name_blocked(ok)[0] is False, ok


def test_name_check_never_reads_manifests():
    import inspect
    src = inspect.getsource(baselines)
    assert "MANIFEST" not in src and "expected_decision" not in src


@pytest.fixture
def tmpdb(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "e.db")
    db.init_db()


def test_aggregate_counts_from_database_only(tmpdb):
    def rec(scn, setup, rep, outcome, decision, ms=None, leaked=0):
        run_eval._record("E1", scn, setup, rep, {"outcome": outcome, "decision": decision, "decision_ms": ms,
                                                  "leaked": leaked, "error": None})
    for rep in (1, 2):
        for scn, dec in [("M1", "BLOCK"), ("M2", "BLOCK"), ("M3", "ALLOW"), ("B1", "ALLOW"), ("B2", "ALLOW"), ("B3", "ALLOW")]:
            rec(scn, "shadowrun", rep, dec, dec, ms=2000 + rep * 100)
            rec(scn, "no_guard", rep, "LEAKED" if scn in ("M1", "M2") else "INSTALLED_NO_LEAK", "NONE",
                leaked={"M1": 1, "M2": 2}.get(scn, 0))
            blocked = scn == "M2"
            rec(scn, "name_check", rep, "BLOCKED_BY_NAME" if blocked else "x", "BLOCK" if blocked else "NONE")
    # flaky false positive in one repeat only still counts as a false positive (conservative)
    rec("B3", "shadowrun", 3, "ESCALATE", "ESCALATE", ms=2500)
    res = run_eval.aggregate("E1")
    rows = {r["setup"]: r for r in res["rows"]}
    assert (rows["shadowrun"]["attacks_prevented"], rows["shadowrun"]["false_positives"]) == (2, 1)
    assert rows["no_guard"]["attacks_prevented"] == 0 and rows["no_guard"]["leaked_tokens"] == 3
    assert rows["name_check"]["attacks_prevented"] == 1
    # 6 x 2100, 6 x 2200 and one 2500 -> the 7th of 13 sorted values is 2200
    assert rows["shadowrun"]["median_ms"] == 2200 and rows["shadowrun"]["max_ms"] == 2500
    assert rows["no_guard"]["median_ms"] is None
    assert res["disclaimer"].startswith("Small demo benchmark: 6 self-written, simulated packages")


def test_reports_contain_disclaimer(tmp_path, monkeypatch):
    monkeypatch.setattr(run_eval, "RESULTS", tmp_path)
    res = {"eval_run_id": "E", "disclaimer": run_eval.DISCLAIMER, "phases": {"fetch_ms": 10.0},
           "rows": [{"setup": "shadowrun", "attacks_prevented": 2, "attacks_total": 3, "false_positives": 0,
                     "benign_total": 3, "leaked_tokens": 0, "median_ms": 2000.0, "max_ms": 3000.0}],
           "matrix": {"M1": {"shadowrun": "BLOCK"}}, "labels": {"M1": {"name": "x", "label": "y"}}}
    run_eval.write_reports(res)
    md = (tmp_path / "results.md").read_text()
    assert "2 of 3" in md and "not real-world detection rates" in md
    assert (tmp_path / "eval_results.csv").read_text().startswith("setup,")
