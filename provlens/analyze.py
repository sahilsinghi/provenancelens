"""Run every module on one file and collect the results in one document."""

from __future__ import annotations

import base64
import hashlib
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PIL import Image

from provlens import __version__, c2pa_check, djpeg, evidence, jpeg, metadata, pixel, qtables, video
from provlens.sniff import extension_mismatch, sniff

ANALYSABLE = {"image/jpeg", "image/png", "image/webp", "image/tiff", "image/gif", "image/bmp", "image/heic", "image/avif"}

# Untrusted files must not be able to exhaust memory: a few hundred KB of PNG can declare a
# 30000x30000 canvas. Above MAX_DECODE_PIXELS the pixels are not decoded at all; above
# MAX_MAP_PIXELS the pixel maps and the double-JPEG statistics (several float copies of the
# image each) are skipped. Both are reported, never silently passed.
MAX_DECODE_PIXELS = 120_000_000
MAX_MAP_PIXELS = 50_000_000
Image.MAX_IMAGE_PIXELS = MAX_DECODE_PIXELS  # Pillow raises DecompressionBombError beyond 2x this
warnings.filterwarnings("ignore", category=Image.DecompressionBombWarning)  # the limits above are enforced explicitly


def _declared_pixels(path: Path) -> tuple[int, int] | None:
    try:
        with Image.open(path) as img:  # reads the header only
            return img.size
    except Exception:  # noqa: BLE001 - the decode stage reports the real error
        return None


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

    size = _declared_pixels(path)
    pixels = size[0] * size[1] if size else 0
    too_big_for_maps = pixels > MAX_MAP_PIXELS

    try:
        result["c2pa"] = c2pa_check.check(path, trust_anchors).to_json()
    except Exception as exc:  # noqa: BLE001
        result["c2pa"] = {"present": False, "state": "error", "error": str(exc),
                          "summary": f"The C2PA check failed ({exc}); whether the file carries credentials is unknown."}

    jinfo = None
    if mime == "image/jpeg":
        try:
            jinfo = jpeg.parse(data)
        except jpeg.NotJpeg as exc:
            result["jpeg"] = None
            result["jpeg_error"] = str(exc)
        if jinfo is not None:
            if too_big_for_maps:
                dj = djpeg.DJpegResult(False, note=f"image of {pixels / 1e6:.0f} MP exceeds the "
                                                   f"{MAX_MAP_PIXELS / 1e6:.0f} MP limit for coefficient statistics").to_json()
            else:
                try:
                    dj = djpeg.detect(data).to_json()
                except Exception as exc:  # noqa: BLE001 - a damaged scan must not abort the whole report
                    dj = djpeg.DJpegResult(False, note=f"the compressed pixel data could not be decoded ({exc})").to_json()
            result["jpeg"] = {
                "width": jinfo.width, "height": jinfo.height, "progressive": jinfo.progressive,
                "subsampling": jinfo.subsampling, "segments": jinfo.app_kinds(),
                "huffman_tables": jinfo.huffman_tables, "trailing_bytes": jinfo.trailing_bytes,
                "qtables": qtables.describe(jinfo.luma, jinfo.chroma) if jinfo.luma else None,
                "luma_table": jinfo.luma, "chroma_table": jinfo.chroma, "djpeg": dj,
            }

    try:
        md, findings = metadata.analyse(path, jinfo.app_kinds() if jinfo else None)
        result["metadata"] = {"empty": md.empty, "summary": md.summary(), "findings": [f.to_json() for f in findings]}
    except Exception as exc:  # noqa: BLE001
        result["metadata"] = {"empty": False, "error": str(exc), "summary": {
            "exif": {}, "gps": {}, "xmp": {}, "png_text_keys": [], "thumbnail_bytes": 0, "reader": "unreadable"}, "findings": [
            {"rule": "M-ERR", "title": "Metadata could not be read", "status": "info", "strength": 0.0,
             "detail": f"The container is damaged or unsupported ({exc})."}]}

    if pixels > MAX_DECODE_PIXELS:
        result["image"] = {"width": size[0], "height": size[1],
                           "error": f"{pixels / 1e6:.0f} MP exceeds the {MAX_DECODE_PIXELS / 1e6:.0f} MP decode limit"}
    else:
        try:
            with Image.open(path) as img:
                img.load()
                work = img.convert("RGB")
        except Exception as exc:  # noqa: BLE001 - truncated or corrupt pixel data
            work = None
            result["image"] = {"width": size[0] if size else None, "height": size[1] if size else None,
                               "error": f"the pixel data could not be decoded ({type(exc).__name__}: {exc})"}
        if work is not None:
            result["image"] = {"width": work.width, "height": work.height,
                               "thumbnail_jpeg_b64": base64.b64encode(pixel.thumbnail_png(work)).decode()}
            if maps and too_big_for_maps:
                result["image"]["maps_skipped"] = (f"{pixels / 1e6:.0f} MP exceeds the {MAX_MAP_PIXELS / 1e6:.0f} MP "
                                                   "limit for pixel maps")
            elif maps:
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
