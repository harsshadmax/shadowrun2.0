"""Bug 4: missing, partial or unparseable syscall evidence is uncertainty, never an implicit pass."""
from pathlib import Path

import pytest

from shadowrun import monitor, policy
from shadowrun.detector import DetectorConfig, RunContext, analyze
from shadowrun.models import Finding

FIX = Path(__file__).parent / "fixtures"
CANARIES = ["/home/sandbox/.ssh/id_rsa"]
CFG = DetectorConfig.from_policy()


def ln(pid, ts, body):
    return f"{pid} {ts} {body}"


EXEC_PIP = ln(5, "1.0", 'execve("/usr/local/bin/pip", ["pip", "install"], 0x7ff /* 3 vars */) = 0')
EXIT_OK = ln(5, "2.0", "+++ exited with 0 +++")


def rules(text, final_exec=None, **ctx_kw):
    pr = monitor.parse_trace(text, final_exec=final_exec)
    ctx = RunContext(canary_paths=CANARIES, trace_problems=pr.completeness_problems(), require_pip_exec=True,
                     init_pid=pr.final_exec_pid, **ctx_kw)
    return {f.rule_id for f in analyze(pr.events, ctx, CFG)}


@pytest.mark.parametrize("name", ["pip_wheel", "pip_sdist"])
def test_real_baselines_are_complete(name):
    text = (FIX / f"{name}.trace.log").read_text()
    pr = monitor.parse_trace(text, final_exec="cat")
    assert pr.completeness_problems() == []
    assert (pr.parse_warnings, pr.unresumed, pr.truncated) == (0, 0, 0)
    assert pr.final_exec_pid == 1 and pr.descendants_still_running == []
    assert rules(text, final_exec="cat", wrapper_cmd=(FIX / f"{name}.cmd").read_text()) == set()


# ---- marker mode: the tracer is attached to the sandbox init (pid 1), which runs `cat` when the package is done
INIT_WAIT = ln(1, "0.5", 'openat(AT_FDCWD</>, "/ctl/go", O_RDONLY) = 3</ctl/go>')
CHILD_EXEC = ln(5, "1.0", 'execve("/usr/local/bin/pip", ["pip", "install"], 0x7ff /* 3 vars */) = 0')
CHILD_EXIT = ln(5, "2.0", "+++ exited with 0 +++")
INIT_CAT = ln(1, "2.1", 'execve("/usr/bin/cat", ["cat"], 0x7ff /* 3 vars */) = 0')


def test_marker_mode_complete_trace():
    text = "\n".join([INIT_WAIT, CHILD_EXEC, CHILD_EXIT, INIT_CAT])
    assert monitor.parse_trace(text, final_exec="cat").completeness_problems() == []
    assert rules(text, final_exec="cat") == set()


def test_marker_mode_missing_completion_marker_is_incomplete():
    text = "\n".join([INIT_WAIT, CHILD_EXEC, CHILD_EXIT])  # the init never reached `cat`: cut short
    pr = monitor.parse_trace(text, final_exec="cat")
    assert any("completion marker missing" in p for p in pr.completeness_problems())
    assert rules(text, final_exec="cat") == {"INCOMPLETE_TRACE"}


def test_marker_mode_a_failed_cat_exec_is_not_the_marker():
    failed = ln(1, "2.1", 'execve("/usr/local/bin/cat", ["cat"], 0x7ff /* 3 vars */) = -1 ENOENT (No such file or directory)')
    pr = monitor.parse_trace("\n".join([INIT_WAIT, CHILD_EXEC, CHILD_EXIT, failed]), final_exec="cat")
    assert pr.final_exec_pid is None and pr.completeness_problems()


def test_marker_mode_a_traced_process_that_never_exited_is_incomplete():
    straggler = ln(6, "1.5", 'openat(AT_FDCWD</work>, "/etc/hosts", O_RDONLY) = 3</etc/hosts>')
    text = "\n".join([INIT_WAIT, CHILD_EXEC, straggler, CHILD_EXIT, INIT_CAT])  # pid 6 has no exit notice
    pr = monitor.parse_trace(text, final_exec="cat")
    assert pr.descendants_still_running == [6]
    assert any("never exited" in p for p in pr.completeness_problems())
    assert "INCOMPLETE_TRACE" in rules(text, final_exec="cat")


def test_marker_mode_forged_cat_is_not_enough_if_the_child_never_finished():
    forged = ln(8, "1.2", 'execve("/usr/bin/cat", ["cat"], 0x7ff /* 3 vars */) = 0')  # a package process running cat
    text = "\n".join([INIT_WAIT, CHILD_EXEC, forged])
    pr = monitor.parse_trace(text, final_exec="cat")
    # only the INIT (pid 1) running cat is the completion marker; a package process running cat proves nothing
    assert pr.final_exec_pid is None and 5 in pr.descendants_still_running
    assert any("completion marker missing" in p for p in pr.completeness_problems())
    assert "INCOMPLETE_TRACE" in rules(text, final_exec="cat")


def test_minimal_complete_trace_is_fine():
    assert rules("\n".join([EXEC_PIP, EXIT_OK])) == set()


def test_empty_trace_is_incomplete():
    assert rules("") == {"INCOMPLETE_TRACE"}
    assert rules("\n\n   \n") == {"INCOMPLETE_TRACE"}


def test_garbage_and_malformed_records_are_incomplete():
    assert rules("\n".join([EXEC_PIP, "not a trace line", EXIT_OK])) == {"INCOMPLETE_TRACE"}
    assert rules("\n".join([EXEC_PIP, "5 notatime openat(", EXIT_OK])) == {"INCOMPLETE_TRACE"}
    pr = monitor.parse_trace("\n".join([EXEC_PIP, "garbage", EXIT_OK]))
    assert pr.parse_warnings == 1 and "unparseable" in pr.completeness_problems()[0]


def test_truncated_trace_without_exit_notice_is_incomplete():
    full = (FIX / "pip_sdist.trace.log").read_text().splitlines()
    cut = "\n".join(full[: len(full) // 2])
    pr = monitor.parse_trace(cut, final_exec="cat")
    assert pr.final_exec_pid is None
    assert any("cut short" in p for p in pr.completeness_problems())
    assert "INCOMPLETE_TRACE" in rules(cut, final_exec="cat")


def test_unresumed_syscall_is_incomplete():
    text = "\n".join([EXEC_PIP, ln(5, "1.5", 'openat(AT_FDCWD</work>, "/home/sandbox/.ssh/id_rsa", O_RDONLY <unfinished ...>'),
                      EXIT_OK])
    pr = monitor.parse_trace(text)
    assert pr.unresumed == 1
    assert "INCOMPLETE_TRACE" in rules(text)


def test_cut_off_strings_are_incomplete():
    # a path longer than strace's -s limit would not match the canary path: that must not look like "no read"
    text = "\n".join([EXEC_PIP, ln(5, "1.5", 'openat(AT_FDCWD</work>, "/home/sandbox/.ssh/id_r"..., O_RDONLY) = 3'),
                      EXIT_OK])
    pr = monitor.parse_trace(text)
    assert pr.truncated == 1
    assert "INCOMPLETE_TRACE" in rules(text)


def test_missing_required_event_pip_never_ran():
    only_opens = "\n".join([ln(5, "1.0", 'openat(AT_FDCWD</work>, "/etc/hosts", O_RDONLY) = 3</etc/hosts>'), EXIT_OK])
    assert rules(only_opens) == {"INCOMPLETE_TRACE"}


def test_complete_trace_with_a_read_still_reports_the_read_not_incompleteness():
    text = "\n".join([EXEC_PIP, ln(5, "1.5", 'openat(AT_FDCWD</work>, "/home/sandbox/.ssh/id_rsa", O_RDONLY) = 3'), EXIT_OK])
    assert rules(text) == {"CANARY_READ"}


def test_evidence_errors_and_tampering_are_findings():
    f = analyze([], RunContext(canary_paths=[], evidence_errors=["trace file missing or unreadable"]), CFG)
    assert [(x.rule_id, x.severity) for x in f] == [("EVIDENCE_UNAVAILABLE", "medium")]
    f = analyze([], RunContext(canary_paths=[], evidence_tampered=["trace file ownership/mode/type changed"]), CFG)
    assert [(x.rule_id, x.severity) for x in f] == [("EVIDENCE_TAMPERED", "critical")]


def test_unit_tests_without_stats_do_not_invent_incompleteness():
    assert analyze([], RunContext(canary_paths=[]), CFG) == []  # caller did not supply trace stats


# ------------------------------------------------------------------ verdicts

def F(rule, sev):
    return Finding(rule_id=rule, severity=sev, message=rule)


def test_incomplete_or_unavailable_evidence_is_denied_and_marked_indeterminate():
    for rule in ("INCOMPLETE_TRACE", "EVIDENCE_UNAVAILABLE"):
        d = policy.decide([F(rule, "medium")])
        assert d.decision == "ESCALATE" and d.indeterminate and d.denied
        assert "escalate_unknown" in d.matched_rules


def test_tampering_blocks_and_is_not_merely_indeterminate():
    d = policy.decide([F("EVIDENCE_TAMPERED", "critical")])
    assert d.decision == "BLOCK" and not d.indeterminate


def test_a_real_block_is_not_downgraded_by_missing_evidence():
    d = policy.decide([F("CANARY_READ", "high"), F("INCOMPLETE_TRACE", "medium")])
    assert d.decision == "BLOCK" and not d.indeterminate


def test_never_allow_with_incomplete_evidence_even_alongside_only_low_findings():
    d = policy.decide([F("INSTALL_FAILED", "low"), F("INCOMPLETE_TRACE", "medium")])
    assert d.decision == "ESCALATE"


def test_pipeline_level_errors_are_indeterminate():
    d = policy.decide_error("parser crashed")
    assert d.decision == "ESCALATE" and d.indeterminate and d.denied
