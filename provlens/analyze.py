"""Run every module on one file and collect the results in one document."""

from __future__ import annotations

import base64
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PIL import Image

from provlens import __version__, c2pa_check, djpeg, evidence, jpeg, metadata, pixel, qtables, video
from provlens.sniff import extension_mismatch, sniff

ANALYSABLE = {"image/jpeg", "image/png", "image/webp", "image/tiff", "image/gif", "image/bmp", "image/heic", "image/avif"}


def analyse(path: Path, trust_anchors: list[Path] | None = None, maps: bool = True) -> dict[str, Any]:
    path = Path(path)
    trust_anchors = [Path(t) for t in trust_anchors or []] or None
    for t in trust_anchors or []:
        if not t.exists():  # a typo must not silently downgrade "Trusted" to "untrusted"
            raise FileNotFoundError(f"trust anchor {t} does not exist")
    t0 = time.perf_counter()
    data = path.read_bytes()
    mime = sniff(path)
    result: dict[str, Any] = {
        "tool": "provenancelens", "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "file": {"name": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "format": mime, "extension_mismatch": extension_mismatch(path, mime),
    }
    if mime in video.VIDEO_TYPES:
        return _analyse_video(path, result, trust_anchors, t0)
    if mime not in ANALYSABLE:
        result["error"] = f"{mime} is not a supported image format"
        result["verdict"] = None
        return result

    try:
        result["c2pa"] = c2pa_check.check(path, trust_anchors).to_json()
    except Exception as exc:  # noqa: BLE001
        result["c2pa"] = {"present": False, "state": "error", "error": str(exc),
                          "summary": f"The C2PA check failed ({exc}); whether the file carries credentials is unknown."}

    jinfo = None
    if mime == "image/jpeg":
        try:
            jinfo = jpeg.parse(data)
            result["jpeg"] = {
                "width": jinfo.width, "height": jinfo.height, "progressive": jinfo.progressive,
                "subsampling": jinfo.subsampling, "segments": jinfo.app_kinds(),
                "huffman_tables": jinfo.huffman_tables, "trailing_bytes": jinfo.trailing_bytes,
                "qtables": qtables.describe(jinfo.luma, jinfo.chroma) if jinfo.luma else None,
                "luma_table": jinfo.luma, "chroma_table": jinfo.chroma,
                "djpeg": djpeg.detect(data).to_json(),
            }
        except jpeg.NotJpeg as exc:
            result["jpeg"] = None
            result["jpeg_error"] = str(exc)

    md, findings = metadata.analyse(path, jinfo.app_kinds() if jinfo else None)
    result["metadata"] = {"empty": md.empty, "summary": md.summary(), "findings": [f.to_json() for f in findings]}

    with Image.open(path) as img:
        img.load()
        work = img.convert("RGB")
    result["image"] = {"width": work.width, "height": work.height,
                       "thumbnail_jpeg_b64": base64.b64encode(pixel.thumbnail_png(work)).decode()}
    if maps:
        px: dict[str, Any] = {}
        q = ((result.get("jpeg") or {}).get("qtables") or {}).get("ijg_quality_estimate")
        for name, m in pixel.all_maps(work, q).items():
            entry = m.to_json()
            entry["heatmap_png_b64"] = base64.b64encode(pixel.heatmap_png(m.pixel_map, work.size, m.regions)).decode()
            px[name] = entry
        result["pixel"] = px
    verdict = evidence.decide(result)
    result["verdict"] = verdict.to_json()
    result["seconds"] = round(time.perf_counter() - t0, 2)
    return result


def _analyse_video(path: Path, result: dict[str, Any], trust_anchors: list[Path] | None, t0: float) -> dict[str, Any]:
    try:
        result["c2pa"] = c2pa_check.check(path, trust_anchors).to_json()
    except Exception as exc:  # noqa: BLE001
        result["c2pa"] = {"present": False, "state": "error", "error": str(exc),
                          "summary": f"The C2PA check failed ({exc}); whether the file carries credentials is unknown."}
    if not video.available():
        result["video"] = {"note": "ffmpeg/ffprobe not found: container rules and frames skipped"}
        findings: list[metadata.Finding] = []
        summ: dict[str, Any] = {}
    else:
        info = video.probe(path)
        summ = video.summary(info)
        findings = video.rules(info)
        shots = video.frames(path, 6, summ["duration_s"])
        sheet = video.contact_sheet(shots)
        result["video"] = {**{k: v for k, v in summ.items() if k != "tags"}, "frames_sampled": len(shots)}
        if sheet:
            result["image"] = {"width": summ.get("width"), "height": summ.get("height"),
                               "thumbnail_jpeg_b64": base64.b64encode(sheet).decode(), "contact_sheet": True}
    tags = summ.get("tags", {})
    meaningful = {k: v for k, v in tags.items() if k.lower() not in ("major_brand", "minor_version", "compatible_brands")}
    result["metadata"] = {"empty": not meaningful, "findings": [f.to_json() for f in findings],
                          "summary": {"exif": {}, "gps": {}, "xmp": {}, "png_text_keys": [], "thumbnail_bytes": 0,
                                      "container": tags, "reader": "ffprobe"}}
    result["verdict"] = evidence.decide(result).to_json()
    result["seconds"] = round(time.perf_counter() - t0, 2)
    return result
