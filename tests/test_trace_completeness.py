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


def rules(text, **ctx_kw):
    pr = monitor.parse_trace(text)
    ctx = RunContext(canary_paths=CANARIES, trace_problems=pr.completeness_problems(), require_pip_exec=True, **ctx_kw)
    return {f.rule_id for f in analyze(pr.events, ctx, CFG)}


@pytest.mark.parametrize("name", ["pip_wheel", "pip_sdist"])
def test_real_baselines_are_complete(name):
    pr = monitor.parse_trace((FIX / f"{name}.trace.log").read_text())
    assert pr.completeness_problems() == []
    assert (pr.lines, pr.parse_warnings, pr.unresumed, pr.truncated, pr.root_exited) == (pr.lines, 0, 0, 0, True)
    assert rules((FIX / f"{name}.trace.log").read_text(), wrapper_cmd=(FIX / f"{name}.cmd").read_text()) == set()


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
    pr = monitor.parse_trace(cut)
    assert not pr.root_exited
    assert any("cut short" in p for p in pr.completeness_problems())
    assert "INCOMPLETE_TRACE" in rules(cut)


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
