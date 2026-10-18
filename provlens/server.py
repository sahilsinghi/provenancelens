"""A small local web UI: upload an image, get the HTML report or the JSON.

Uploads are written to a private temporary file, analysed and deleted; nothing
is kept. The server binds to 127.0.0.1 by default.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from provlens import __version__

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
<label id="drop" for="file"><b>Choose or drop an image</b><br><span id="fname">JPEG, PNG, WebP, TIFF, HEIC</span></label>
<input id="file" type="file" name="file" accept="image/*" required>
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


def create_app(trust_anchors: list[Path] | None = None, max_bytes: int = 40 * 1024 * 1024) -> FastAPI:
    app = FastAPI(title="ProvenanceLens", version=__version__)
    anchors = trust_anchors or None

    async def _analyse(upload: UploadFile) -> dict:
        from provlens.analyze import analyse

        data = await upload.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise HTTPException(413, f"file larger than {max_bytes // (1024 * 1024)} MB")
        if not data:
            raise HTTPException(400, "empty upload")
        name = Path(upload.filename or "upload").name
        fd, tmp = tempfile.mkstemp(prefix="provlens-", suffix=Path(name).suffix[:10])
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            result = analyse(Path(tmp), anchors)
        finally:
            os.unlink(tmp)
        result["file"]["name"] = name
        if result.get("error"):
            raise HTTPException(415, result["error"])
        return result

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return INDEX

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

    return app
