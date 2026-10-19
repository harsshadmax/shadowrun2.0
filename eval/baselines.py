"""Baselines for the benchmark. Neither baseline sees the package manifests (labels or expected decisions)."""
from shadowrun import pipeline

# Known-bad names (not the fixture names) plus edit distance <= 2 to a popular-names list.
BLOCKLIST = {"requessts", "python-dateutill", "urlib3", "colourama", "djanga", "beautifulsoup"}
POPULAR = ["requests", "numpy", "pandas", "flask", "django", "urllib3", "boto3", "setuptools", "cryptography",
           "pyyaml", "jinja2", "pytest", "scipy", "pillow", "sqlalchemy", "matplotlib", "tensorflow", "beautifulsoup4",
           "colorama", "certifi", "idna", "six", "click", "fastapi", "pydantic", "aiohttp", "paramiko", "selenium"]
MIN_LEN = 5  # avoid flagging short names that are close to anything


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def name_blocked(spec: str) -> tuple[bool, str]:
    name = spec.split("==")[0].strip().lower().replace("_", "-")
    if name in BLOCKLIST:
        return True, "known-bad name"
    if name in POPULAR:
        return False, "exact popular name"
    if len(name) >= MIN_LEN:
        for p in POPULAR:
            if len(p) >= MIN_LEN and edit_distance(name, p) <= 2:
                return True, f"within edit distance 2 of {p}"
    return False, "no match"


def run_no_guard(spec: str, scenario_id: str) -> dict:
    r = pipeline.run_exposed(spec, agent_id="eval", setup="no_guard", scenario_id=scenario_id)
    return {"outcome": "LEAKED" if r["leaked_tokens"] else "INSTALLED_NO_LEAK", "decision": "NONE",
            "decision_ms": None, "leaked": len(r["leaked_tokens"]), "error": r["error"]}


def run_name_check(spec: str, scenario_id: str) -> dict:
    blocked, why = name_blocked(spec)
    if blocked:
        return {"outcome": "BLOCKED_BY_NAME", "decision": "BLOCK", "decision_ms": None, "leaked": 0, "error": None,
                "why": why}
    r = pipeline.run_exposed(spec, agent_id="eval", setup="name_check", scenario_id=scenario_id)
    return {"outcome": "LEAKED" if r["leaked_tokens"] else "INSTALLED_NO_LEAK", "decision": "NONE",
            "decision_ms": None, "leaked": len(r["leaked_tokens"]), "error": r["error"]}


def run_shadowrun(spec: str, scenario_id: str) -> dict:
    run = pipeline.run_action(spec, agent_id="eval", setup="shadowrun", scenario_id=scenario_id)
    return {"outcome": run["decision"], "decision": run["decision"], "decision_ms": run["decision_ms"],
            "leaked": 0,  # nothing is installed outside the sandbox
            "error": run["error"]}


SETUPS = {"no_guard": run_no_guard, "name_check": run_name_check, "shadowrun": run_shadowrun}
