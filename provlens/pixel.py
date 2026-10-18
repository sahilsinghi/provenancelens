"""Pixel-level maps that point an analyst at regions worth a closer look.

* **ELA** (error-level analysis): re-save at a fixed quality (80 instead of
  90 when the image itself was saved near 90, see ``ela_quality``) and measure
  how much each block changes. Regions with a different compression history
  can stand out, but so do edges, text and saturated areas, which is why ELA
  is never a verdict on its own.
* **Noise level**: Donoho's MAD estimate on the finest diagonal wavelet band,
  per block. A region pasted from another camera or upscaled from another
  source can have a different noise level. On the labelled set it localised
  no splice after a final JPEG save, so it is shown but never scored.
* **JPEG ghosts** (Farid, 2009): re-save at a range of qualities. A region that
  was previously compressed at quality q differs least from the copy saved at
  q, so it shows up as a "ghost" in that copy's difference map.

Each map is reduced to blocks, scored with a robust z-score (median / MAD),
and its connected outlier blocks become candidate regions.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from PIL import Image
from scipy import ndimage

BLOCK = 16


@dataclass
class MapResult:
    name: str
    blocks: np.ndarray  # per-block statistic
    regions: list[dict[str, Any]] = field(default_factory=list)
    score: float = 0.0  # strongest localised anomaly (robust z), 0 if none
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "score": round(self.score, 2), "regions": self.regions, "note": self.note}


def _luma(img: Image.Image) -> np.ndarray:
    return np.asarray(img.convert("L"), dtype=np.float64)


def _block_mean(a: np.ndarray, block: int = BLOCK) -> np.ndarray:
    h, w = a.shape[0] // block * block, a.shape[1] // block * block
    a = a[:h, :w]
    return a.reshape(h // block, block, w // block, block).mean(axis=(1, 3))


def _save(img: Image.Image, quality: int) -> Image.Image:
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "JPEG", quality=quality)
    buf.seek(0)
    return Image.open(buf).convert("RGB")


def robust_z(blocks: np.ndarray, floor: float = 1e-9) -> np.ndarray:
    med = np.median(blocks)
    mad = max(np.median(np.abs(blocks - med)) * 1.4826, floor)
    return (blocks - med) / mad


def regions_from(z: np.ndarray, threshold: float, block: int = BLOCK, min_blocks: int = 4,
                 two_sided: bool = False) -> list[dict[str, Any]]:
    mask = np.abs(z) > threshold if two_sided else z > threshold
    mask = ndimage.binary_opening(mask, structure=np.ones((2, 2))) if mask.sum() > 8 else mask
    labels, n = ndimage.label(mask)
    out = []
    total = z.size
    for i in range(1, n + 1):
        ys, xs = np.where(labels == i)
        if len(ys) < min_blocks:
            continue
        out.append({
            "bbox": [int(xs.min() * block), int(ys.min() * block), int((xs.max() + 1) * block), int((ys.max() + 1) * block)],
            "blocks": int(len(ys)),
            "area_fraction": round(len(ys) / total, 4),
            "mean_z": round(float(np.abs(z[labels == i]).mean()), 2),
        })
    out.sort(key=lambda r: -r["mean_z"] * r["blocks"])
    return out[:5]


def _texture_mask(img: Image.Image, block: int = BLOCK) -> np.ndarray:
    """Blocks with real texture; flat and saturated blocks give meaningless ELA/noise values."""
    y = _luma(img)
    grad = np.hypot(ndimage.sobel(y, 0), ndimage.sobel(y, 1))
    g = _block_mean(grad, block)
    mean = _block_mean(y, block)
    return (g > np.percentile(g, 10)) & (mean > 8) & (mean < 247)


def ela(img: Image.Image, quality: int = 90) -> MapResult:
    rgb = img.convert("RGB")
    diff = np.abs(np.asarray(rgb, dtype=np.int16) - np.asarray(_save(rgb, quality), dtype=np.int16)).max(axis=2)
    blocks = _block_mean(diff.astype(np.float64))
    # normalise by local texture so plain edges light up less
    grad = _block_mean(np.hypot(ndimage.sobel(_luma(rgb), 0), ndimage.sobel(_luma(rgb), 1)))
    norm = blocks / (1.0 + 0.05 * grad)
    z = robust_z(norm)
    z[~_texture_mask(rgb)] = 0
    regions = regions_from(z, 3.5)
    res = MapResult("ela", blocks, regions, float(max((r["mean_z"] for r in regions), default=0.0)))
    res.note = f"re-saved at quality {quality}; mean error level {diff.mean():.2f}"
    res.pixel_map = diff  # type: ignore[attr-defined]
    return res


def noise(img: Image.Image, block: int = 32) -> MapResult:
    """Local noise level from the finest diagonal wavelet band (Donoho's MAD estimator).

    The diagonal Haar detail of natural images is dominated by sensor noise rather
    than edges, and the median absolute deviation ignores the few edge pixels that
    remain, so the estimate tracks noise more than texture. After a final JPEG
    save the signal is weak; see docs/evaluation.md for its measured hit rate.
    """
    y = _luma(img)
    h, w = y.shape[0] // 2 * 2, y.shape[1] // 2 * 2
    y = y[:h, :w]
    d = (y[0::2, 0::2] - y[0::2, 1::2] - y[1::2, 0::2] + y[1::2, 1::2]) / 2.0
    half = block // 2
    hb, wb = d.shape[0] // half, d.shape[1] // half
    cells = np.abs(d[:hb * half, :wb * half]).reshape(hb, half, wb, half).transpose(0, 2, 1, 3).reshape(hb, wb, -1)
    sigma = np.median(cells, axis=2) / 0.6745
    z = robust_z(np.log(sigma + 0.25), floor=0.1)
    z[~_texture_mask(img, block)[:hb, :wb]] = 0
    regions = regions_from(z, 3.0, block=block, min_blocks=2, two_sided=True)
    res = MapResult("noise", sigma, regions, float(max((r["mean_z"] for r in regions), default=0.0)))
    res.note = f"median noise sigma {np.median(sigma):.2f} grey levels"
    res.pixel_map = np.kron(sigma, np.ones((block, block)))  # type: ignore[attr-defined]
    return res


def ghosts(img: Image.Image, qualities: range = range(40, 100, 5)) -> MapResult:
    """JPEG ghosts with each block's difference curve normalised by its own mean.

    Raw re-save differences scale with local detail; dividing each block's curve
    D_q by its average over q removes that, leaving the *shape* of the curve. A
    region previously compressed at quality q dips at q.
    """
    rgb = img.convert("RGB")
    y = _luma(rgb)
    qs = list(qualities)
    curves = np.stack([_block_mean((y - _luma(_save(rgb, q))) ** 2) for q in qs])
    norm = curves / (curves.mean(axis=0, keepdims=True) + 1e-6)
    mask = _texture_mask(rgb)
    best = (0.0, qs[0], norm[0], [])
    display = (-np.inf, qs[0], norm[0])  # strongest dip even below threshold, so the map is never blank
    for i, q in enumerate(qs[:-2]):  # the highest qualities dip everywhere for an image last saved there
        z = -robust_z(norm[i])
        z[~mask] = 0
        regions = [r for r in regions_from(z, 3.0) if r["area_fraction"] < 0.5]
        score = max((r["mean_z"] for r in regions), default=0.0)
        if score > best[0]:
            best = (score, q, norm[i], regions)
        if float(np.percentile(z, 99)) > display[0]:
            display = (float(np.percentile(z, 99)), q, norm[i])
    score, q, nd, regions = best
    if not regions:
        q, nd = display[1], display[2]
    res = MapResult("ghost", nd, regions, float(score))
    res.note = f"strongest ghost at quality {q}" if regions else f"no localised ghost (map shown at quality {q})"
    res.ghost_quality = q  # type: ignore[attr-defined]
    span = nd.max() - nd.min() + 1e-9
    res.pixel_map = np.kron((nd.max() - nd) / span, np.ones((BLOCK, BLOCK)))  # type: ignore[attr-defined]
    return res


def ela_quality(jpeg_quality: int | None, default: int = 90, alternative: int = 80) -> int:
    """Re-save quality for ELA: never (almost) the quality the image was last saved at.

    Re-saving at the image's own quality is nearly idempotent, so the error map is
    ~0 everywhere, the robust spread collapses and harmless rounding noise becomes
    a huge z-score. On the labelled set, switching to 80 for images near q90 cut
    single-save false alarms from 11% to 2% without losing a single splice.
    """
    return alternative if jpeg_quality is not None and abs(jpeg_quality - default) <= 2 else default


def all_maps(img: Image.Image, jpeg_quality: int | None = None) -> dict[str, MapResult]:
    return {"ela": ela(img, quality=ela_quality(jpeg_quality)), "noise": noise(img), "ghost": ghosts(img)}


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

_STOPS = np.array([[0, 0, 4], [87, 16, 110], [188, 55, 84], [249, 142, 9], [252, 255, 164]], dtype=np.float64)  # inferno-like


def colorize(values: np.ndarray) -> np.ndarray:
    v = np.clip(values, 0, 1) * (len(_STOPS) - 1)
    i = np.clip(v.astype(int), 0, len(_STOPS) - 2)
    t = (v - i)[..., None]
    return (_STOPS[i] * (1 - t) + _STOPS[i + 1] * t).astype(np.uint8)


def heatmap_png(values: np.ndarray, size: tuple[int, int], regions: list[dict[str, Any]] | None = None,
                max_width: int = 640) -> bytes:
    from PIL import ImageDraw

    v = values.astype(np.float64)
    hi = np.percentile(v, 99.5) or 1.0
    img = Image.fromarray(colorize(v / hi)).resize(size, Image.NEAREST)
    draw = ImageDraw.Draw(img)
    for r in regions or []:
        draw.rectangle(r["bbox"], outline=(80, 220, 255), width=max(2, size[0] // 300))
    if img.width > max_width:
        img = img.resize((max_width, int(img.height * max_width / img.width)))
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def thumbnail_png(img: Image.Image, max_width: int = 640) -> bytes:
    t = img.convert("RGB")
    if t.width > max_width:
        t = t.resize((max_width, int(t.height * max_width / t.width)), Image.LANCZOS)
    buf = io.BytesIO()
    t.save(buf, "JPEG", quality=85)
    return buf.getvalue()
