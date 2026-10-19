"""Dashboard pages and HTML fragments. Jinja autoescape is ON everywhere: package names, metadata and
sink contents are untrusted input."""
import asyncio
import time
from contextlib import closing
from datetime import datetime, timezone

import jinja2
import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.templating import Jinja2Templates

from . import audit, config, db, stats

router = APIRouter()
_env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(config.ROOT / "dashboard" / "templates")),
                          autoescape=True)
_env.filters["secs"] = lambda ms: "n/a" if ms is None else ("<0.1s" if ms < 50 else f"{ms / 1000:.1f}s")
templates = Jinja2Templates(env=_env)
_doctor_cache = {"ts": 0.0, "checks": None}


def scenarios() -> list[dict]:
    out = [yaml.safe_load(p.read_text()) for p in sorted((config.ROOT / "packages" / "src").glob("*/MANIFEST.yaml"))]
    return sorted(out, key=lambda m: m["id"])


def _ctx(request: Request, page: str, **kw) -> dict:
    from . import api  # lazy: api imports this module
    return {"token": api.TOKEN, "page": page, **kw}


async def _checks() -> tuple[list[dict], bool]:
    from . import api
    from .doctor import run_checks
    busy = api.RUN_LOCK.locked()
    if _doctor_cache["checks"] is None or (not busy and time.time() - _doctor_cache["ts"] > 60):
        _doctor_cache["checks"] = await asyncio.to_thread(run_checks)
        _doctor_cache["ts"] = time.time()
    return _doctor_cache["checks"], busy


def _tpl(request: Request, name: str, **ctx):
    db.init_db()
    return templates.TemplateResponse(request, name, ctx)


@router.get("/")
def index(request: Request):
    db.init_db()
    today = datetime.now(timezone.utc).strftime("%B %d, %Y").replace(" 0", " ")
    return templates.TemplateResponse(request, "index.html",
                                      _ctx(request, "overview", scenarios=scenarios(), today=today))


@router.get("/demo")
def demo(request: Request):
    return templates.TemplateResponse(request, "demo.html", _ctx(request, "demo"))


@router.get("/ui/kpis")
def ui_kpis(request: Request):
    return _tpl(request, "_kpis.html", k=stats.kpis())


@router.get("/ui/note")
def ui_note(request: Request):
    return _tpl(request, "_note.html", k=stats.kpis())


@router.get("/ui/heatmap")
def ui_heatmap(request: Request, tab: str = "findings"):
    return _tpl(request, "_heatmap.html", h=stats.heatmap(tab), k=stats.kpis())


@router.get("/ui/runs")
def ui_runs(request: Request, f: str = "all", page: int = 1):
    return _tpl(request, "_runs.html", p=stats.runs_page(f, page))


@router.get("/ui/run/{run_id}")
def ui_run(request: Request, run_id: str):
    return _tpl(request, "_detail.html", run=stats.detail(run_id))


@router.get("/ui/doctor")
async def ui_doctor(request: Request):
    checks, busy = await _checks()
    return templates.TemplateResponse(request, "_doctor.html",
                                      {"checks": checks, "ok": all(c["ok"] for c in checks), "busy": busy})


@router.get("/ui/isolation")
async def ui_isolation(request: Request):
    checks, busy = await _checks()
    by = {c["n"]: c for c in checks}
    items = [("Internet blocked", by.get(3)), ("Sink reachable", by.get(4)),
             ("strace recording", by.get(5)), ("Read-only root", by.get(6))]
    return templates.TemplateResponse(request, "_isolation.html", {"items": items, "busy": busy})


@router.get("/ui/agent")
def ui_agent(request: Request):
    from . import api
    with closing(db.connect()) as c:
        evs = [dict(r) for r in c.execute("SELECT * FROM agent_events ORDER BY id DESC LIMIT 3")][::-1]
    return templates.TemplateResponse(request, "_agent.html", {"events": evs, "running": api.AGENT_STATE["running"]})


@router.get("/ui/audit-verify")
def ui_audit_verify(request: Request):
    db.init_db()
    return templates.TemplateResponse(request, "_audit.html", {"res": audit.verify()})
