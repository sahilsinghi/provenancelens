"""A one-image summary of an analysis ("report card"), optionally C2PA-signed.

The card shows the image, the three pixel maps, the verdict and the top
signals. When signed, its manifest carries:

* a ``c2pa.created`` action by ProvenanceLens (IPTC ``digitalCreation``),
* the analysed image as a ``componentOf`` ingredient, so the original's own
  credentials (if any) travel with the card, and
* an ``org.provenancelens.analysis`` assertion with the analysed file's SHA-256,
  the verdict and every signal's contribution, so the card's claims are
  machine-checkable and bound to the exact bytes that were analysed.
"""

from __future__ import annotations

import base64
import io
import textwrap
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

W = 1200
INK, MUTED, BG, PANEL, ACCENT = (29, 32, 37), (95, 102, 112), (246, 246, 243), (255, 255, 255), (154, 52, 18)
LEVEL_BG = {"strong": (254, 243, 199), "moderate": (254, 243, 199), "weak": (241, 241, 239), "none": (220, 252, 231)}


def _font(size: int) -> ImageFont.ImageFont:
    return ImageFont.load_default(size=size)


def _b64img(s: str | None) -> Image.Image | None:
    if not s:
        return None
    return Image.open(io.BytesIO(base64.b64decode(s))).convert("RGB")


def _fit(img: Image.Image, w: int, h: int) -> Image.Image:
    img = img.copy()
    img.thumbnail((w, h))
    return img


def _wrap(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, font, fill, width_chars: int, gap: int = 4) -> int:
    x, y = xy
    for line in textwrap.wrap(text, width_chars):
        draw.text((x, y), line, font=font, fill=fill)
        y += font.size + gap
    return y


def render(result: dict[str, Any]) -> bytes:
    v = result["verdict"]
    img = Image.new("RGB", (W, 1000), BG)
    d = ImageDraw.Draw(img)
    d.text((32, 26), "ProvenanceLens report card", font=_font(26), fill=INK)
    d.text((32, 62), f"{result['file']['name']} · {result['format']} · SHA-256 {result['file']['sha256'][:32]}…",
            font=_font(15), fill=MUTED)

    thumb = _b64img(result.get("image", {}).get("thumbnail_jpeg_b64"))
    th = 0
    if thumb:
        t = _fit(thumb, 400, 300)
        img.paste(t, (32, 100))
        th = t.height
    x0 = 460
    head = textwrap.wrap(v["headline"], 66)
    sub = textwrap.wrap(f"Editing evidence: {v['editing_level']} (score {v['editing_score']:.2f}). "
                        f"AI generation: {v['generation']}", 84)
    bottom = 100 + 32 + len(head) * 22 + 8 + len(sub) * 19
    d.rounded_rectangle((x0, 100, W - 32, bottom), 10, fill=LEVEL_BG.get(v["editing_level"], PANEL), outline=(225, 225, 220))
    y = _wrap(d, (x0 + 18, 116), v["headline"], _font(18), INK, 66)
    _wrap(d, (x0 + 18, y + 8), " ".join(sub), _font(15), MUTED, 84)

    y = max(100 + th, bottom) + 30
    d.text((32, y), "Signals (strength x weight)", font=_font(18), fill=INK)
    y += 30
    for s in v["signals"][:7]:
        weighted = s["supports"] in ("edited", "generated", "authentic", "declared")
        tag = f"{s['supports']:<10}" + (f" {s['contribution']:.2f}" if weighted else "")
        d.text((32, y), tag, font=_font(14), fill=ACCENT if s["supports"] == "edited" else MUTED)
        y = _wrap(d, (190, y), f"{s['title']}: {s['detail']}", _font(14), INK, 132, gap=3) + 6

    if result.get("pixel"):
        y += 10
        cell = (W - 64 - 2 * 16) // 3
        for i, name in enumerate(("ela", "noise", "ghost")):
            hm = _b64img(result["pixel"][name].get("heatmap_png_b64"))
            if hm is None:
                continue
            t = _fit(hm, cell, 220)
            x = 32 + i * (cell + 16)
            img.paste(t, (x, y + 22))
            d.text((x, y), name.upper() + " map", font=_font(14), fill=MUTED)
        y += 22 + 230
    d.text((32, y + 8), "Pointers for an analyst, not proof. Full report: provlens analyze --html.", font=_font(13), fill=MUTED)
    img = img.crop((0, 0, W, min(y + 40, img.height))) if y + 40 < img.height else img
    if y + 40 > 1000:
        canvas = Image.new("RGB", (W, y + 40), BG)
        canvas.paste(img, (0, 0))
        img = canvas
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def analysis_assertion(result: dict[str, Any]) -> dict[str, Any]:
    v = result["verdict"]
    return {
        "label": "org.provenancelens.analysis",
        "data": {
            "tool": f"provenancelens {result['version']}",
            "analysed": {"name": result["file"]["name"], "sha256": result["file"]["sha256"], "format": result["format"]},
            "c2pa_state": (result.get("c2pa") or {}).get("state"),
            "editing_level": v["editing_level"], "editing_score": v["editing_score"],
            "generation_score": v["generation_score"], "headline": v["headline"],
            "signals": [{"id": s["id"], "supports": s["supports"], "contribution": s["contribution"]} for s in v["signals"]],
        },
    }


def write(result: dict[str, Any], out: Path, analysed: Path | None = None, identity_dir: Path | None = None) -> Path:
    """Write the card PNG; sign it when ``identity_dir`` holds a test identity."""
    png = render(result)
    if identity_dir is None:
        out.write_bytes(png)
        return out
    from provlens import testsign

    ident = testsign.load_identity(identity_dir)
    tmp = out.with_suffix(".unsigned.png")
    tmp.write_bytes(png)
    try:
        testsign.sign(tmp, out, ident, title=out.name,
                      actions=[{"action": "c2pa.created",
                                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"}],
                      assertions=[analysis_assertion(result)], component=analysed)
    finally:
        tmp.unlink(missing_ok=True)
    return out
