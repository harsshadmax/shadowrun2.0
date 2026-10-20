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
UI_REFRESH_MIN_GAP_S = 20
_ui_refresh = {"ts": 0.0}


def scenarios() -> list[dict]:
    out = [yaml.safe_load(p.read_text()) for p in sorted((config.ROOT / "packages" / "src").glob("*/MANIFEST.yaml"))]
    return sorted(out, key=lambda m: m["id"])


def _ctx(request: Request, page: str, **kw) -> dict:
    from . import api  # lazy: api imports this module
    return {"token": api.TOKEN, "page": page, **kw}


async def _health() -> dict:
    """The one shared health view. The dashboard never runs a check while a scan is in progress (it would share
    the sandbox with the scan); it re-checks only when idle and the status is not a fresh PASS."""
    from . import health
    view = health.peek()
    busy = health.busy()
    if view["state"] != "PASS" and not busy and time.time() - _ui_refresh["ts"] > UI_REFRESH_MIN_GAP_S:
        _ui_refresh["ts"] = time.time()
        await asyncio.to_thread(health.refresh, "dashboard")
        view = health.peek()
    return {**view, "busy": busy}


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
    return templates.TemplateResponse(request, "_doctor.html", {"h": await _health()})


@router.get("/ui/isolation")
async def ui_isolation(request: Request):
    h = await _health()
    by = {c["n"]: c for c in h["checks"]}
    items = [("Internet blocked", by.get(3)), ("Sink reachable", by.get(4)), ("strace recording", by.get(5)),
             ("Read-only root", by.get(6)), ("Evidence protected", by.get(8))]
    return templates.TemplateResponse(request, "_isolation.html", {"items": items, "h": h})


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
