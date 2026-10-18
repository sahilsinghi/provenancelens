"""A small local web UI: upload an image, get the HTML report or the JSON.

Uploads are written to a private temporary file, analysed and deleted; nothing
is kept. The server binds to 127.0.0.1 by default and is hardened for
untrusted uploads:

* request bodies are counted while they stream in and cut off at the limit,
  before anything is spooled to disk;
* when bound to loopback, only loopback ``Host`` headers are accepted, so a web
  page cannot reach it through DNS rebinding;
* analyses run in worker threads, at most ``max_concurrent`` at a time;
* every response carries no-sniff / no-framing headers and HTML responses a
  strict Content-Security-Policy (reports embed attacker-controlled metadata).
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from provlens import __version__

LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "::1", "[::1]"]
MULTIPART_OVERHEAD = 64 * 1024
REPORT_CSP = ("default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; "
              "form-action 'none'; frame-ancestors 'none'")
INDEX_CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; "
             "form-action 'self'; frame-ancestors 'none'")

INDEX = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>ProvenanceLens</title>
<style>
:root{--bg:#f6f6f3;--panel:#fff;--ink:#1d2025;--muted:#5f6670;--line:#d9d9d3;--accent:#9a3412}
@media (prefers-color-scheme: dark){:root{--bg:#121315;--panel:#1b1d20;--ink:#e7e7e4;--muted:#9aa0a8;--line:#2d3035;--accent:#fb923c}}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,sans-serif}
main{max-width:720px;margin:0 auto;padding:48px 16px}
h1{font-size:24px;margin:0 0 6px}p{color:var(--muted)}
label{display:block;border:2px dashed var(--line);border-radius:12px;background:var(--panel);padding:40px 16px;text-align:center;cursor:pointer}
label.drag{border-color:var(--accent)}input[type=file]{display:none}
button{margin-top:14px;background:var(--accent);color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:15px;cursor:pointer}
#status{margin-top:12px;color:var(--muted);min-height:1.5em}
</style></head><body><main>
<h1>ProvenanceLens</h1>
<p>Drop an image to check its content credentials (C2PA), metadata and compression history. Every signal in the
report says what was measured and how much it counts. Files are analysed on this machine and deleted straight away.</p>
<form id="f" method="post" action="/analyze" enctype="multipart/form-data">
<label id="drop" for="file"><b>Choose or drop an image</b><br><span id="fname">JPEG, PNG, WebP, TIFF, HEIC, MP4, MOV</span></label>
<input id="file" type="file" name="file" accept="image/*,video/mp4,video/quicktime" required>
<button type="submit">Analyse</button><div id="status"></div></form>
<p style="font-size:13px">API: <code>POST /api/analyze</code> (multipart field <code>file</code>) returns JSON.</p>
<script>
const drop=document.getElementById('drop'),file=document.getElementById('file'),fname=document.getElementById('fname');
file.addEventListener('change',()=>{fname.textContent=file.files[0]?file.files[0].name:''});
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('drag')}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('drag')}));
drop.addEventListener('drop',ev=>{file.files=ev.dataTransfer.files;fname.textContent=file.files[0].name});
document.getElementById('f').addEventListener('submit',()=>{document.getElementById('status').textContent='Analysing…'});
</script></main></body></html>"""


class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Reject a request as soon as its body exceeds ``limit`` bytes (declared or streamed)."""

    def __init__(self, app, limit: int):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.limit):
            return await self._reject(send)
        seen = 0
        started = False

        async def counted_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.limit:
                    raise _TooLarge
            return message

        async def tracked_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted_receive, tracked_send)
        except _TooLarge:
            if not started:
                await self._reject(send)

    async def _reject(self, send):
        body = b'{"detail":"upload too large"}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


def _safe_suffix(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9.]", "", Path(name).suffix)[:10]


def create_app(trust_anchors: list[Path] | None = None, max_bytes: int = 40 * 1024 * 1024,
               allowed_hosts: list[str] | None = None, max_concurrent: int = 2) -> FastAPI:
    """``allowed_hosts`` defaults to loopback names; pass ``["*"]`` only behind your own proxy."""
    app = FastAPI(title="ProvenanceLens", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    anchors = trust_anchors or None
    slots = asyncio.Semaphore(max_concurrent)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cache-Control", "no-store")
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers.setdefault("Content-Security-Policy", REPORT_CSP)
        return response

    async def _analyse(upload: UploadFile) -> dict:
        from provlens.analyze import analyse

        data = await upload.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise HTTPException(413, f"file larger than {max_bytes // (1024 * 1024)} MB")
        if not data:
            raise HTTPException(400, "empty upload")
        name = Path(upload.filename or "upload").name[:200]
        fd, tmp = tempfile.mkstemp(prefix="provlens-", suffix=_safe_suffix(name))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            async with slots:
                result = await run_in_threadpool(analyse, Path(tmp), anchors)
        finally:
            os.unlink(tmp)
        result["file"]["name"] = name
        if result.get("error"):
            raise HTTPException(415, result["error"])
        return result

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(INDEX, headers={"Content-Security-Policy": INDEX_CSP})

    @app.post("/analyze", response_class=HTMLResponse)
    async def analyze_html(file: UploadFile) -> str:
        from provlens.report import render_html

        return render_html(await _analyse(file))

    @app.post("/api/analyze")
    async def analyze_json(file: UploadFile) -> JSONResponse:
        return JSONResponse(await _analyse(file))

    @app.get("/healthz")
    def health() -> dict:
        return {"ok": True, "version": __version__}

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or LOOPBACK_HOSTS)
    app.add_middleware(BodyLimitMiddleware, limit=max_bytes + MULTIPART_OVERHEAD)
    return app
