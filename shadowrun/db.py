"""SQLite storage. Per-call connections (never shared across threads), WAL, busy_timeout, parameterized queries."""
import json
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, created_at TEXT, agent_id TEXT, package_name TEXT, package_version TEXT,
  sha256 TEXT, setup TEXT, state TEXT, decision TEXT, decision_reason TEXT, container_ip TEXT,
  report_json TEXT, phase_ms_json TEXT, decision_ms REAL, scenario_id TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, rule_id TEXT, severity TEXT, message TEXT, evidence_json TEXT);
CREATE TABLE IF NOT EXISTS agent_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, agent_id TEXT, run_id TEXT, kind TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, event_type TEXT, run_id TEXT, payload_json TEXT,
  prev_hash TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS eval_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT, eval_run_id TEXT, scenario_id TEXT, setup TEXT, repeat INTEGER,
  outcome TEXT, decision TEXT, decision_ms REAL, leaked_tokens INTEGER);
CREATE TABLE IF NOT EXISTS doctor_runs (
  id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT, ok INTEGER, checks_json TEXT, reason TEXT);
"""

RUN_COLUMNS = {"created_at", "agent_id", "package_name", "package_version", "sha256", "setup", "state",
               "decision", "decision_reason", "container_ip", "report_json", "phase_ms_json", "decision_ms",
               "scenario_id"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    with closing(connect()) as c:
        c.executescript(SCHEMA)
        c.commit()


def insert_run(run_id: str, **fields) -> None:
    fields = {k: v for k, v in fields.items() if k in RUN_COLUMNS}
    fields.setdefault("created_at", now_iso())
    cols = ["id"] + list(fields)
    with closing(connect()) as c:
        c.execute(f"INSERT INTO runs ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                  [run_id] + list(fields.values()))
        c.commit()


def update_run(run_id: str, **fields) -> None:
    fields = {k: v for k, v in fields.items() if k in RUN_COLUMNS}
    if not fields:
        return
    with closing(connect()) as c:
        c.execute(f"UPDATE runs SET {','.join(k + '=?' for k in fields)} WHERE id=?", list(fields.values()) + [run_id])
        c.commit()


def insert_doctor_run(doctor_id: str, started_at: str, finished_at: str, ok: bool, checks_json: str, reason: str) -> None:
    with closing(connect()) as c:
        c.execute("INSERT OR REPLACE INTO doctor_runs (id, started_at, finished_at, ok, checks_json, reason) "
                  "VALUES (?,?,?,?,?,?)", (doctor_id, started_at, finished_at, 1 if ok else 0, checks_json, reason))
        c.commit()


def get_doctor_run(doctor_id: str) -> dict | None:
    with closing(connect()) as c:
        r = c.execute("SELECT * FROM doctor_runs WHERE id=?", (doctor_id,)).fetchone()
        if not r:
            return None
        out = dict(r)
        out["ok"] = bool(out["ok"])
        out["checks"] = json.loads(out.pop("checks_json") or "[]")
        return out


def add_findings(run_id: str, findings) -> None:
    with closing(connect()) as c:
        c.executemany(
            "INSERT INTO findings (run_id, rule_id, severity, message, evidence_json) VALUES (?,?,?,?,?)",
            [(run_id, f.rule_id, f.severity, f.message, json.dumps(f.evidence, default=str)) for f in findings])
        c.commit()


def add_agent_event(agent_id: str, run_id: str | None, kind: str, message: str) -> None:
    with closing(connect()) as c:
        c.execute("INSERT INTO agent_events (ts, agent_id, run_id, kind, message) VALUES (?,?,?,?,?)",
                  (now_iso(), agent_id, run_id, kind, message))
        c.commit()


def get_run(run_id: str) -> dict | None:
    with closing(connect()) as c:
        r = c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not r:
            return None
        out = dict(r)
        out["findings"] = [dict(f, evidence=json.loads(f.pop("evidence_json") or "{}")) for f in
                           (dict(x) for x in c.execute("SELECT * FROM findings WHERE run_id=? ORDER BY id", (run_id,)))]
        return out


def demo_reset() -> None:
    """Clear runs, findings, agent events, the sink log and old traces. The audit log is kept."""
    import shutil
    with closing(connect()) as c:
        for t in ("runs", "findings", "agent_events"):
            c.execute(f"DELETE FROM {t}")
        c.commit()
    if config.SINK_LOG.exists():
        config.SINK_LOG.write_text("")
    shutil.rmtree(config.TRACE_DIR, ignore_errors=True)


def list_runs(limit: int = 50) -> list[dict]:
    with closing(connect()) as c:
        return [dict(r) for r in c.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,))]
