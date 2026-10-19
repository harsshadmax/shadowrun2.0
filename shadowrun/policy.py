"""Policy engine: all rules evaluated, strictest decision wins (BLOCK > ESCALATE > ALLOW). Fails closed.
ESCALATE is treated as denied in this build (shown as "needs human review"). No LLM is involved."""
from pathlib import Path

import yaml
from pydantic import BaseModel

from . import config
from .models import SEVERITY_ORDER, Finding

STRICTNESS = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
WHEN_KEYS = {"any_rule", "max_severity_at_most"}
ALLOW_REASON = "No suspicious behaviour in the tested run (limited evidence)."
LABELS = {"ALLOW": "allowed", "ESCALATE": "needs human review (denied)", "BLOCK": "blocked"}


class PolicyError(Exception):
    pass


class Decision(BaseModel):
    decision: str
    matched_rules: list[str]
    findings: list[Finding]
    confidence: str = "limited"
    reason: str

    @property
    def denied(self) -> bool:
        return self.decision != "ALLOW"

    @property
    def label(self) -> str:
        return LABELS[self.decision]

    @property
    def exit_code(self) -> int:
        return {"ALLOW": 0, "BLOCK": 2, "ESCALATE": 3}[self.decision]


def load_policy(path: Path | None = None) -> dict:
    try:
        data = yaml.safe_load((path or config.ROOT / "policies" / "default.yaml").read_text())
    except Exception as e:
        raise PolicyError(f"cannot load policy: {e}") from e
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("rules"), list):
        raise PolicyError("policy must be a mapping with version: 1 and a rules list")
    for r in data["rules"]:
        if not isinstance(r, dict) or {"id", "when", "decision"} - set(r):
            raise PolicyError(f"malformed rule: {r!r}")
        if r["decision"] not in STRICTNESS:
            raise PolicyError(f"rule {r['id']}: unknown decision {r['decision']!r}")
        when = r["when"]
        if not isinstance(when, dict) or not when or set(when) - WHEN_KEYS:
            raise PolicyError(f"rule {r['id']}: unsupported 'when' {when!r}")
        if "max_severity_at_most" in when and when["max_severity_at_most"] not in SEVERITY_ORDER:
            raise PolicyError(f"rule {r['id']}: unknown severity {when['max_severity_at_most']!r}")
    return data


def _matches(when: dict, findings: list[Finding]) -> bool:
    ok = True
    if "any_rule" in when:
        ids = {f.rule_id for f in findings}
        ok &= bool(ids & set(when["any_rule"]))
    if "max_severity_at_most" in when:
        top = max((SEVERITY_ORDER[f.severity] for f in findings), default=0)
        ok &= top <= SEVERITY_ORDER[when["max_severity_at_most"]]
    return ok


def decide(findings: list[Finding], policy: dict | None = None, policy_path: Path | None = None) -> Decision:
    """Never raises: any internal error becomes a BLOCK."""
    try:
        pol = policy or load_policy(policy_path)
        matched = [(r["id"], r["decision"]) for r in pol["rules"] if _matches(r["when"], findings)]
        if not matched:  # nothing vouched for this run
            return Decision(decision="ESCALATE", matched_rules=[], findings=findings,
                            reason="No policy rule matched; needs human review (fail closed).")
        final = max((d for _, d in matched), key=STRICTNESS.get)
        ids = [i for i, _ in matched]
        if final == "ALLOW":
            reason = ALLOW_REASON
        else:
            reasons = "; ".join(f"{f.rule_id}: {f.message}" for f in findings
                                if SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER["medium"])
            reason = f"{LABELS[final].capitalize()}. {reasons}" if reasons else f"{LABELS[final].capitalize()}."
        return Decision(decision=final, matched_rules=ids, findings=findings, reason=reason)
    except Exception as e:
        return Decision(decision="BLOCK", matched_rules=[], findings=list(findings) if isinstance(findings, list) else [],
                        reason=f"Policy evaluation failed ({type(e).__name__}: {e}); blocked (fail closed).")


def decide_error(message: str, block: bool = False) -> Decision:
    """Pipeline-level failure (fetch error, doctor failure, ...): never ALLOW."""
    d = "BLOCK" if block else "ESCALATE"
    return Decision(decision=d, matched_rules=[], findings=[], reason=f"{message}; {LABELS[d]} (fail closed).")
