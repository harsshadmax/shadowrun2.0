"""FastAPI app (bound to 127.0.0.1). The Docker SDK is blocking, so runs go to worker threads; a lock
serialises them so timings stay clean. Mutating routes need the X-Demo-Token header."""
import asyncio
import json
import os
import secrets
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import audit, config, db, pipeline

TOKEN = os.environ.get("SHADOWRUN_DEMO_TOKEN") or secrets.token_urlsafe(16)
RUN_LOCK = threading.Lock()  # one sandbox run at a time
STREAMS: dict[str, "RunStream"] = {}
AGENT_STATE = {"running": False}
API = "/api/v1"


class RunStream:
    """Append-only event list so late SSE subscribers can replay."""

    def __init__(self):
        self.events: list[tuple[str, dict]] = []
        self.done = False

    def emit(self, kind: str, data: dict):
        self.events.append((kind, data))


@asynccontextmanager
async def lifespan(app):
    config.DATA.mkdir(parents=True, exist_ok=True)
    p = config.DATA / "demo_token"
    p.write_text(TOKEN)
    os.chmod(p, 0o600)
    db.init_db()
    yield


app = FastAPI(title="Shadow-Run", lifespan=lifespan)


def _err(code: str, message: str, status: int, request: Request):
    rid = getattr(request.state, "request_id", uuid.uuid4().hex[:8])
    return JSONResponse({"error": {"code": code, "message": message, "request_id": rid}}, status_code=status)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request.state.request_id = uuid.uuid4().hex[:8]
    try:
        resp = await call_next(request)
    except Exception:  # never leak a stack trace
        return _err("internal_error", "Internal error", 500, request)
    resp.headers["X-Request-Id"] = request.state.request_id
    return resp


@app.exception_handler(StarletteHTTPException)
async def http_exc(request, exc):
    return _err(f"http_{exc.status_code}", str(exc.detail), exc.status_code, request)


@app.exception_handler(RequestValidationError)
async def validation_exc(request, exc):
    return _err("invalid_request", "Request validation failed", 422, request)


def need_token(x_demo_token: str | None = Header(default=None)):
    if not x_demo_token or not secrets.compare_digest(x_demo_token, TOKEN):
        raise HTTPException(401, "Missing or invalid X-Demo-Token")


class ActionIn(BaseModel):
    spec: str
    agent_id: str = "api"
    wait: bool = True


class SpecIn(BaseModel):
    spec: str


def _run_gated(spec: str, agent_id: str, run_id: str | None = None, stream: RunStream | None = None) -> dict:
    with RUN_LOCK:
        run = pipeline.run_action(spec, agent_id=agent_id, run_id=run_id, emit=stream.emit if stream else None)
    out = pipeline.summarize(run)
    if stream:
        stream.emit("end", {"run_id": out["run_id"]})
        stream.done = True
    return out


@app.get(f"{API}/health")
def health():
    return {"status": "ok"}


@app.get(f"{API}/doctor")
async def doctor_route():
    from .doctor import run_checks
    checks = await asyncio.to_thread(run_checks)
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


@app.post(f"{API}/actions", dependencies=[Depends(need_token)])
async def post_action(body: ActionIn):
    run_id = uuid.uuid4().hex[:12]
    stream = RunStream()
    STREAMS[run_id] = stream
    fut = asyncio.create_task(asyncio.to_thread(_run_gated, body.spec, body.agent_id, run_id, stream))
    if not body.wait:
        return JSONResponse({"run_id": run_id, "state": "STARTED"}, status_code=202)
    return await fut


@app.get(f"{API}/runs")
def get_runs(limit: int = 50):
    return {"runs": db.list_runs(min(max(limit, 1), 200))}


@app.get(API + "/runs/{run_id}")
def get_run(run_id: str):
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    return run


@app.get(API + "/runs/{run_id}/stream")
async def stream_run(run_id: str):
    s = STREAMS.get(run_id)
    if s is None:
        raise HTTPException(404, "No live stream for this run")

    async def gen():
        i = 0
        while True:
            while i < len(s.events):
                kind, data = s.events[i]
                i += 1
                yield f"event: {kind}\ndata: {json.dumps(data, default=str)}\n\n"
            if s.done and i >= len(s.events):
                return
            await asyncio.sleep(0.1)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.post(f"{API}/demo/unguarded", dependencies=[Depends(need_token)])
async def demo_unguarded(body: SpecIn):
    def work():
        with RUN_LOCK:
            return pipeline.run_exposed(body.spec, agent_id="demo-unguarded")
    return await asyncio.to_thread(work)


@app.get(f"{API}/sink/events")
def sink_events(limit: int = 100):
    if not config.SINK_LOG.exists():
        return {"events": []}
    lines = config.SINK_LOG.read_text(errors="replace").splitlines()[-min(max(limit, 1), 500):]
    events = []
    for ln in lines:
        try:
            events.append(json.loads(ln))
        except Exception:
            pass
    return {"events": events}


def _agent_worker():
    from agent.scripted_agent import AGENT_ID, run_task

    def act(spec):
        return _run_gated(spec, AGENT_ID)

    def log(kind, message, run_id=None):
        db.add_agent_event(AGENT_ID, run_id, kind, message)

    try:
        run_task(act, log, workdir=config.DATA / "agent_workspace")
    except Exception as e:
        db.add_agent_event(AGENT_ID, None, "CONTINUE", f"Agent stopped with an error: {type(e).__name__}")
    finally:
        AGENT_STATE["running"] = False


@app.post(f"{API}/agent/run", dependencies=[Depends(need_token)])
def agent_run():
    if AGENT_STATE["running"]:
        raise HTTPException(409, "Agent already running")
    AGENT_STATE["running"] = True
    threading.Thread(target=_agent_worker, daemon=True).start()
    return JSONResponse({"started": True}, status_code=202)


@app.get(f"{API}/agent/events")
def agent_events(since_id: int = 0):
    from contextlib import closing
    with closing(db.connect()) as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM agent_events WHERE id>? ORDER BY id", (since_id,))]
    return {"events": rows, "running": AGENT_STATE["running"]}


@app.get(f"{API}/audit")
def audit_list(limit: int = 100):
    return {"entries": audit.list_entries(min(max(limit, 1), 500))}


@app.get(f"{API}/audit/verify")
def audit_verify():
    return audit.verify()


@app.post(f"{API}/admin/demo-reset", dependencies=[Depends(need_token)])
def demo_reset():
    db.demo_reset()
    STREAMS.clear()
    return {"ok": True}


EVAL_STATE = {"running": False}


def _eval_worker(repeats: int):
    try:
        from eval.run_eval import main as eval_main
        with RUN_LOCK:  # the benchmark owns the sandbox until it finishes
            eval_main(repeats)
    finally:
        EVAL_STATE["running"] = False


@app.post(f"{API}/eval/run", dependencies=[Depends(need_token)])
def eval_run(repeats: int = 1):
    if EVAL_STATE["running"]:
        raise HTTPException(409, "Benchmark already running")
    EVAL_STATE["running"] = True
    threading.Thread(target=_eval_worker, args=(min(max(repeats, 1), 5),), daemon=True).start()
    return JSONResponse({"started": True, "repeats": min(max(repeats, 1), 5)}, status_code=202)


@app.get(f"{API}/eval/results")
def eval_results():
    """Latest benchmark summary written by `shadowrun eval`: {available, disclaimer, rows, phases, ...}."""
    p = config.ROOT / "eval" / "results" / "latest.json"
    data = json.loads(p.read_text()) if p.exists() else {"available": False}
    data["running"] = EVAL_STATE["running"]
    return data


# Dashboard (pages + fragments + static files); imported last because ui reads api.TOKEN lazily.
from fastapi.staticfiles import StaticFiles  # noqa: E402

from . import ui  # noqa: E402

app.include_router(ui.router)
app.mount("/static", StaticFiles(directory=str(config.ROOT / "dashboard" / "static")), name="static")
