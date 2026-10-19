"""Sink: logs every request it receives to /data/sink.jsonl (one JSON line each)."""
import json
import time

from fastapi import FastAPI, Request

app = FastAPI()
LOG = "/data/sink.jsonl"
MAX_BODY = 64 * 1024


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str):
    body = (await request.body())[:MAX_BODY].decode("utf-8", errors="replace")
    event = {
        "ts": time.time(),
        "source_ip": request.client.host if request.client else None,
        "method": request.method,
        "path": request.url.path + (("?" + request.url.query) if request.url.query else ""),
        "headers": dict(request.headers),
        "body": body,
    }
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
        f.flush()
    return {"ok": True}
