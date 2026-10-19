"""Insert-only, hash-chained audit log. Never UPDATE or DELETE audit_log rows anywhere."""
import hashlib
import json
from contextlib import closing

from . import db

GENESIS = "GENESIS"
EVENT_TYPES = {"ACTION_RECEIVED", "FETCHED", "SANDBOX_STARTED", "SANDBOX_FINISHED", "FINDINGS_RECORDED",
               "DECISION_MADE", "EVAL_STARTED", "EVAL_FINISHED"}


def canonical_json(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, ts: str, event_type: str, run_id: str | None, payload_json: str) -> str:
    return hashlib.sha256(f"{prev_hash}{ts}{event_type}{run_id or ''}{payload_json}".encode()).hexdigest()


def append(event_type: str, run_id: str | None, payload: dict) -> str:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown audit event type {event_type}")
    payload_json = canonical_json(payload)
    with closing(db.connect()) as c:
        c.isolation_level = None
        c.execute("BEGIN IMMEDIATE")
        try:
            row = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            ts = db.now_iso()
            h = compute_hash(prev, ts, event_type, run_id, payload_json)
            c.execute("INSERT INTO audit_log (ts, event_type, run_id, payload_json, prev_hash, hash) "
                      "VALUES (?,?,?,?,?,?)", (ts, event_type, run_id, payload_json, prev, h))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    return h


def verify() -> dict:
    """Recompute the chain. Returns {ok, checked, broken_id}."""
    prev = GENESIS
    n = 0
    with closing(db.connect()) as c:
        for r in c.execute("SELECT * FROM audit_log ORDER BY id"):
            expect = compute_hash(prev, r["ts"], r["event_type"], r["run_id"], r["payload_json"])
            if r["prev_hash"] != prev or r["hash"] != expect:
                return {"ok": False, "checked": n, "broken_id": r["id"]}
            prev = r["hash"]
            n += 1
    return {"ok": True, "checked": n, "broken_id": None}


def list_entries(limit: int = 100) -> list[dict]:
    with closing(db.connect()) as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]
