"""Read-only aggregates for the dashboard. Every number shown comes from these queries over the runs/findings tables."""
import json
import statistics
from contextlib import closing

import yaml

from . import config, db

RULES = ["CANARY_EXFIL", "CANARY_READ", "NET_OUTBOUND", "PERSISTENCE_WRITE", "HASH_MISMATCH",
         "UNEXPECTED_EXEC", "WRITE_OUTSIDE_ALLOWED"]
DECISIONS = ["ALLOW", "BLOCK", "ESCALATE"]
FILTERS = {"all": None, "allow": ("ALLOW",), "block": ("BLOCK",), "review": ("ESCALATE",), "unguarded": ("NONE",)}
PAGE_SIZE = 8
MAX_COLS = 8


def _scan_rows(c):
    return [dict(r) for r in c.execute(
        "SELECT id, package_name, decision, decision_ms FROM runs WHERE setup='shadowrun' AND decision IS NOT NULL")]


def kpis() -> dict:
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


def heatmap(tab: str = "findings") -> dict:
    """rows x packages grid of counts. tab=findings: runs in which a detector rule fired; tab=decisions: run counts."""
    tab = tab if tab in ("findings", "decisions") else "findings"
    with closing(db.connect()) as c:
        pkgs = [r[0] for r in c.execute(
            "SELECT DISTINCT package_name FROM runs WHERE setup='shadowrun' AND decision IS NOT NULL")]
        if tab == "findings":
            cells = {(r[1], r[0]): r[2] for r in c.execute(
                "SELECT r.package_name, f.rule_id, COUNT(DISTINCT r.id) FROM findings f JOIN runs r ON r.id=f.run_id "
                "WHERE r.setup='shadowrun' GROUP BY 1, 2")}
            rows = RULES
        else:
            cells = {(r[1], r[0]): r[2] for r in c.execute(
                "SELECT package_name, decision, COUNT(*) FROM runs WHERE setup='shadowrun' AND decision IS NOT NULL "
                "GROUP BY 1, 2")}
            rows = DECISIONS
    order = _manifest_order()
    cols = sorted(pkgs, key=lambda p: (order.index(p) if p in order else len(order), p))[:MAX_COLS]
    grid = [[cells.get((r, p), 0) for p in cols] for r in rows]
    return {"tab": tab, "rows": rows, "cols": cols, "grid": grid, "max": max((n for row in grid for n in row), default=0)}


def runs_page(flt: str = "all", page: int = 1) -> dict:
    flt = flt if flt in FILTERS else "all"
    where, args = "", []
    if FILTERS[flt]:
        where = " WHERE decision IN (%s)" % ",".join("?" * len(FILTERS[flt]))
        args = list(FILTERS[flt])
    with closing(db.connect()) as c:
        total = c.execute(f"SELECT COUNT(*) FROM runs{where}", args).fetchone()[0]
        pages = max(1, -(-total // PAGE_SIZE))
        page = min(max(page, 1), pages)
        rows = [dict(r) for r in c.execute(
            f"SELECT r.*, (SELECT COUNT(*) FROM findings f WHERE f.run_id=r.id) AS n_findings FROM runs r"
            f"{where.replace('decision', 'r.decision')} ORDER BY r.created_at DESC LIMIT ? OFFSET ?",
            args + [PAGE_SIZE, (page - 1) * PAGE_SIZE])]
        counts = {k: c.execute("SELECT COUNT(*) FROM runs" + (
            " WHERE decision IN (%s)" % ",".join("?" * len(v)) if v else ""), list(v or ())).fetchone()[0]
                  for k, v in FILTERS.items()}
    first = (page - 1) * PAGE_SIZE + 1 if total else 0
    return {"rows": rows, "filter": flt, "page": page, "pages": pages, "total": total, "counts": counts,
            "first": first, "last": first + len(rows) - 1 if rows else 0}


PHASE_LABELS = [("fetch_ms", "Fetched"), ("hash_ms", "Hashed"), ("sandbox_ms", "Sandbox install"),
                ("analyze_ms", "Analyzed"), ("decide_ms", "Decided")]


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
    run["timeline"] = [{"label": lbl, "ms": phases[k]} for k, lbl in PHASE_LABELS if k in phases]
    run["report"] = report
    return run
