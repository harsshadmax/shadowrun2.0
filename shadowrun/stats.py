"""Read-only aggregates for the dashboard. Every number shown comes from these queries over the runs/findings
tables; nothing is estimated, padded or invented."""
import json
import statistics
from contextlib import closing
from datetime import datetime, timedelta, timezone

import yaml

from . import config, db, health

RULES = ["CANARY_EXFIL", "CANARY_READ", "NET_OUTBOUND", "PERSISTENCE_WRITE", "HASH_MISMATCH", "EVIDENCE_TAMPERED",
         "UNEXPECTED_EXEC", "WRITE_OUTSIDE_ALLOWED", "INCOMPLETE_TRACE", "EVIDENCE_UNAVAILABLE"]
DECISIONS = ["ALLOW", "BLOCK", "ESCALATE"]
FILTERS = {"all": None, "allow": ("ALLOW",), "block": ("BLOCK",), "review": ("ESCALATE",), "unguarded": ("NONE",)}
INDETERMINATE_RULES = ("INCOMPLETE_TRACE", "EVIDENCE_UNAVAILABLE")
WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "all": None}
PAGE_SIZE = 8
MAX_COLS = 8
SPARK_BUCKETS = 12


def window_bounds(window: str, now: datetime | None = None):
    """(start, previous_start) as ISO strings; None means unbounded."""
    delta = WINDOWS.get(window, WINDOWS["24h"])
    if delta is None:
        return None, None
    now = now or datetime.now(timezone.utc)
    return (now - delta).isoformat(), (now - 2 * delta).isoformat()


def _where(clauses: list[str]) -> str:
    return (" WHERE " + " AND ".join(clauses)) if clauses else ""


def _scan_rows(c, since: str | None = None, until: str | None = None):
    cl, args = ["setup='shadowrun'", "decision IS NOT NULL"], []
    if since:
        cl.append("created_at >= ?")
        args.append(since)
    if until:
        cl.append("created_at < ?")
        args.append(until)
    return [dict(r) for r in c.execute(
        f"SELECT id, package_name, decision, decision_ms, created_at FROM runs{_where(cl)}", args)]


def _spark(values: list[int], w: int = 210, h: int = 52, pad: int = 4) -> dict:
    """SVG geometry for a small area chart; flat zero line when there is no data."""
    n = len(values)
    top = max(values) if values and max(values) > 0 else 1
    xs = [pad + i * (w - 2 * pad) / max(n - 1, 1) for i in range(n)]
    ys = [h - pad - (v / top) * (h - 2 * pad) for v in values]
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    area = f"M{xs[0]:.1f},{h - pad} L" + " L".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys)) + f" L{xs[-1]:.1f},{h - pad} Z" if n else ""
    return {"points": pts, "area": area, "w": w, "h": h, "last": (xs[-1], ys[-1]) if n else (pad, h - pad),
            "any": any(values)}


def _buckets(rows: list[dict], decision: str, start: str | None, now: datetime) -> list[int]:
    if not rows:
        return [0] * SPARK_BUCKETS
    t0 = datetime.fromisoformat(start) if start else min(datetime.fromisoformat(r["created_at"]) for r in rows)
    span = max((now - t0).total_seconds(), 1.0)
    out = [0] * SPARK_BUCKETS
    for r in rows:
        if r["decision"] != decision:
            continue
        i = int((datetime.fromisoformat(r["created_at"]) - t0).total_seconds() / span * SPARK_BUCKETS)
        out[min(max(i, 0), SPARK_BUCKETS - 1)] += 1
    return out


def cards(window: str = "24h", now: datetime | None = None) -> dict:
    """Blocked / Allowed / Needs-review counts for the window, change vs the previous window, and a bucketed series."""
    window = window if window in WINDOWS else "24h"
    now = now or datetime.now(timezone.utc)
    start, prev = window_bounds(window, now)
    with closing(db.connect()) as c:
        rows = _scan_rows(c, start)
        before = _scan_rows(c, prev, start) if prev else []
        indet = {r[0] for r in c.execute(
            "SELECT DISTINCT run_id FROM findings WHERE rule_id IN (?,?)", INDETERMINATE_RULES)}
    total = len(rows)
    out = {"window": window, "total": total, "median_ms": None, "cards": []}
    ms = [r["decision_ms"] for r in rows if r["decision_ms"]]
    out["median_ms"] = statistics.median(ms) if ms else None
    spec = [("BLOCK", "Blocked", "bad"), ("ALLOW", "Allowed", "ok"), ("ESCALATE", "Needs review", "warn")]
    for decision, label, tone in spec:
        n = sum(1 for r in rows if r["decision"] == decision)
        n_prev = sum(1 for r in before if r["decision"] == decision)
        series = _buckets(rows, decision, start, now)
        out["cards"].append({
            "decision": decision, "label": label, "tone": tone, "count": n,
            "pct": round(100 * n / total) if total else 0,
            "delta": (n - n_prev) if prev else None, "spark": _spark(series), "series": series,
            "indeterminate": sum(1 for r in rows if r["decision"] == decision and r["id"] in indet),
        })
    return out


def kpis() -> dict:
    """All-time totals (used by the review badge and the header)."""
    with closing(db.connect()) as c:
        rows = _scan_rows(c)
    total = len(rows)
    count = lambda d: sum(1 for r in rows if r["decision"] == d)  # noqa: E731
    ms = sorted(r["decision_ms"] for r in rows if r["decision_ms"])
    return {
        "total": total, "blocked": count("BLOCK"), "allowed": count("ALLOW"), "review": count("ESCALATE"),
        "blocked_pct": round(100 * count("BLOCK") / total) if total else 0,
        "allowed_pct": round(100 * count("ALLOW") / total) if total else 0,
        "fastest": ms[0] if ms else None, "median": statistics.median(ms) if ms else None,
        "slowest": ms[-1] if ms else None,
    }


def _manifest_order() -> list[str]:
    out = [yaml.safe_load(p.read_text()) for p in sorted((config.ROOT / "packages" / "src").glob("*/MANIFEST.yaml"))]
    return [m["name"] for m in sorted(out, key=lambda m: m["id"])]


def heatmap(tab: str = "findings", window: str = "all") -> dict:
    """rows x packages grid of counts. tab=findings: runs in which a detector rule fired; tab=decisions: run counts."""
    tab = tab if tab in ("findings", "decisions") else "findings"
    start, _ = window_bounds(window)
    cl, args = ["r.setup='shadowrun'", "r.decision IS NOT NULL"], []
    if start:
        cl.append("r.created_at >= ?")
        args.append(start)
    where = _where(cl)
    with closing(db.connect()) as c:
        pkgs = [r[0] for r in c.execute(f"SELECT DISTINCT r.package_name FROM runs r{where}", args)]
        if tab == "findings":
            cells = {(r[1], r[0]): r[2] for r in c.execute(
                f"SELECT r.package_name, f.rule_id, COUNT(DISTINCT r.id) FROM findings f JOIN runs r ON r.id=f.run_id"
                f"{where} GROUP BY 1, 2", args)}
            rows = RULES
        else:
            cells = {(r[1], r[0]): r[2] for r in c.execute(
                f"SELECT r.package_name, r.decision, COUNT(*) FROM runs r{where} GROUP BY 1, 2", args)}
            rows = DECISIONS
    order = _manifest_order()
    cols = sorted(pkgs, key=lambda p: (order.index(p) if p in order else len(order), p))[:MAX_COLS]
    if tab == "findings":  # hide rules that never fired to keep the grid readable, but keep the core detectors
        keep = {"CANARY_EXFIL", "CANARY_READ", "NET_OUTBOUND", "PERSISTENCE_WRITE", "UNEXPECTED_EXEC"}
        rows = [r for r in rows if r in keep or any(cells.get((r, p), 0) for p in cols)]
    grid = [[cells.get((r, p), 0) for p in cols] for r in rows]
    return {"tab": tab, "window": window, "rows": rows, "cols": cols, "grid": grid,
            "max": max((n for row in grid for n in row), default=0)}


def runs_page(flt: str = "all", page: int = 1, q: str = "") -> dict:
    flt = flt if flt in FILTERS else "all"
    q = (q or "").strip()[:60]
    cl, args = [], []
    if FILTERS[flt]:
        cl.append("r.decision IN (%s)" % ",".join("?" * len(FILTERS[flt])))
        args += list(FILTERS[flt])
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        cl.append("(r.package_name LIKE ? ESCAPE '\\' OR r.id LIKE ? ESCAPE '\\' OR r.agent_id LIKE ? ESCAPE '\\')")
        args += [like, like, like]
    where = _where(cl)
    with closing(db.connect()) as c:
        total = c.execute(f"SELECT COUNT(*) FROM runs r{where}", args).fetchone()[0]
        pages = max(1, -(-total // PAGE_SIZE))
        page = min(max(page, 1), pages)
        rows = [dict(r) for r in c.execute(
            "SELECT r.*, (SELECT COUNT(*) FROM findings f WHERE f.run_id=r.id) AS n_findings, "
            "EXISTS(SELECT 1 FROM findings f WHERE f.run_id=r.id AND f.rule_id IN (?,?)) AS indet "
            f"FROM runs r{where} ORDER BY r.created_at DESC LIMIT ? OFFSET ?",
            list(INDETERMINATE_RULES) + args + [PAGE_SIZE, (page - 1) * PAGE_SIZE])]
        for r in rows:
            r["indeterminate"] = bool(r.pop("indet")) and r["decision"] != "BLOCK"
        counts = {k: c.execute("SELECT COUNT(*) FROM runs" + (
            " WHERE decision IN (%s)" % ",".join("?" * len(v)) if v else ""), list(v or ())).fetchone()[0]
                  for k, v in FILTERS.items()}
    first = (page - 1) * PAGE_SIZE + 1 if total else 0
    return {"rows": rows, "filter": flt, "page": page, "pages": pages, "total": total, "counts": counts, "q": q,
            "first": first, "last": first + len(rows) - 1 if rows else 0}


def recent(n: int = 4) -> list[dict]:
    with closing(db.connect()) as c:
        return [dict(r) for r in c.execute(
            "SELECT id, package_name, package_version, decision, created_at, setup FROM runs "
            "WHERE decision IS NOT NULL ORDER BY created_at DESC LIMIT ?", (n,))]


PHASE_LABELS = [("gate_ms", "Doctor gate"), ("fetch_ms", "Fetch"), ("hash_ms", "Hash"), ("sandbox_ms", "Sandbox"),
                ("analyze_ms", "Analyze"), ("decide_ms", "Decide")]


def detail(run_id: str) -> dict | None:
    with closing(db.connect()) as c:
        if run_id == "latest":
            r = c.execute("SELECT id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
            if not r:
                return None
            run_id = r["id"]
    run = db.get_run(run_id)
    if not run:
        return None
    phases = json.loads(run.get("phase_ms_json") or "{}")
    report = json.loads(run.get("report_json") or "{}")
    run["report"] = report
    top = max([phases.get(k, 0) for k, _ in PHASE_LABELS] + [1])
    run["timeline"] = [{"label": lbl, "ms": phases[k], "pct": max(2, round(100 * phases[k] / top))}
                       for k, lbl in PHASE_LABELS if k in phases]
    run["indeterminate"] = run.get("decision") != "BLOCK" and any(
        f["rule_id"] in INDETERMINATE_RULES for f in run.get("findings", []))
    # Which doctor check gated THIS run, and how it relates to the status shown right now (never silently merged).
    ref = report.get("doctor") or {}
    stored = db.get_doctor_run(ref["id"]) if ref.get("id") else None
    run["doctor_at_run"] = {**ref, "checks": stored["checks"] if stored else []} if ref else None
    run["doctor_relation"] = health.correlate(report, health.peek())
    return run
