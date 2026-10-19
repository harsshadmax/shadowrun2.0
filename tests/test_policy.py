import pytest

from shadowrun import policy
from shadowrun.models import Finding


def F(rule, sev):
    return Finding(rule_id=rule, severity=sev, message=f"{rule} happened")


def test_no_findings_allows_with_limited_evidence():
    d = policy.decide([])
    assert d.decision == "ALLOW" and d.matched_rules == ["allow_clean"]
    assert "limited evidence" in d.reason and d.confidence == "limited"
    assert d.exit_code == 0 and not d.denied


def test_low_only_allows():
    assert policy.decide([F("INSTALL_FAILED", "low")]).decision == "ALLOW"


def test_medium_escalates_and_is_denied():
    d = policy.decide([F("UNEXPECTED_EXEC", "medium")])
    assert d.decision == "ESCALATE" and d.denied and d.exit_code == 3
    assert "needs human review" in d.label


def test_block_rules():
    for rule, sev in [("CANARY_EXFIL", "critical"), ("HASH_MISMATCH", "critical"), ("CANARY_READ", "high"),
                      ("PERSISTENCE_WRITE", "high"), ("NET_OUTBOUND", "high")]:
        d = policy.decide([F(rule, sev)])
        assert d.decision == "BLOCK" and d.exit_code == 2, rule


def test_strictest_wins_and_all_matches_recorded():
    d = policy.decide([F("UNEXPECTED_EXEC", "medium"), F("CANARY_READ", "high"), F("CANARY_EXFIL", "critical")])
    assert d.decision == "BLOCK"
    assert d.matched_rules == ["block_exfil", "block_secrets", "escalate_odd"]
    assert "CANARY_READ" in d.reason


def test_block_beats_allow_even_if_allow_would_match():
    # only low findings + a high one: allow_clean must not match
    d = policy.decide([F("INSTALL_FAILED", "low"), F("NET_OUTBOUND", "high")])
    assert d.decision == "BLOCK" and "allow_clean" not in d.matched_rules


def test_unknown_rule_with_high_severity_fails_closed():
    d = policy.decide([F("BRAND_NEW_RULE", "high")])
    assert d.decision == "ESCALATE" and d.matched_rules == []


def test_bad_policy_file_fails_closed(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("version: 2\nrules: []\n")
    assert policy.decide([], policy_path=p).decision == "BLOCK"
    assert policy.decide([], policy_path=tmp_path / "missing.yaml").decision == "BLOCK"
    p.write_text("version: 1\nrules:\n  - {id: x, when: {surprise: 1}, decision: ALLOW}\n")
    assert policy.decide([], policy_path=p).decision == "BLOCK"
    p.write_text("version: 1\nrules:\n  - {id: x, when: {any_rule: [A]}, decision: MAYBE}\n")
    assert policy.decide([], policy_path=p).decision == "BLOCK"


def test_internal_error_blocks_not_allows():
    bad = [Finding.model_construct(rule_id="X", severity="weird", message="m", evidence={})]
    d = policy.decide(bad)
    assert d.decision == "BLOCK" and "fail" in d.reason.lower()


def test_empty_rules_does_not_allow():
    d = policy.decide([], policy={"version": 1, "rules": []})
    assert d.decision == "ESCALATE"


def test_decide_error_never_allows():
    assert policy.decide_error("fetch failed").decision == "ESCALATE"
    assert policy.decide_error("doctor failed", block=True).decision == "BLOCK"
