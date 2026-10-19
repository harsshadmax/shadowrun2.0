"""Dashboard pages and HTML fragments. Jinja autoescape is ON everywhere: package names, metadata and
sink contents are untrusted input."""
import asyncio
import time

import jinja2
import yaml
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

from . import audit, config, db

router = APIRouter()
_env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(config.ROOT / "dashboard" / "templates")),
                          autoescape=True)
templates = Jinja2Templates(env=_env)
_doctor_cache = {"ts": 0.0, "checks": None}


def scenarios() -> list[dict]:
    out = [yaml.safe_load(p.read_text()) for p in sorted((config.ROOT / "packages" / "src").glob("*/MANIFEST.yaml"))]
    return sorted(out, key=lambda m: m["id"])


def _ctx(request: Request, page: str, **kw) -> dict:
    from . import api  # lazy: api imports this module
    return {"token": api.TOKEN, "page": page, **kw}


@router.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", _ctx(request, "gate", scenarios=scenarios()))


@router.get("/demo")
def demo(request: Request):
    return templates.TemplateResponse(request, "demo.html", _ctx(request, "demo"))


@router.get("/ui/runs")
def ui_runs(request: Request):
    db.init_db()
    return templates.TemplateResponse(request, "_runs.html", {"runs": db.list_runs(15)})


@router.get("/ui/doctor")
async def ui_doctor(request: Request):
    from . import api
    from .doctor import run_checks
    busy = api.RUN_LOCK.locked()
    if _doctor_cache["checks"] is None or (not busy and time.time() - _doctor_cache["ts"] > 60):
        _doctor_cache["checks"] = await asyncio.to_thread(run_checks)
        _doctor_cache["ts"] = time.time()
    checks = _doctor_cache["checks"]
    return templates.TemplateResponse(request, "_doctor.html",
                                      {"checks": checks, "ok": all(c["ok"] for c in checks), "busy": busy})


@router.get("/ui/audit-verify")
def ui_audit_verify(request: Request):
    db.init_db()
    return templates.TemplateResponse(request, "_audit.html", {"res": audit.verify()})
