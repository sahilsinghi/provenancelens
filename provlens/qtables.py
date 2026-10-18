"""Quantisation-table fingerprints: which encoder last saved this JPEG?

Every JPEG encoder ships its own quantisation tables (or its own way of
scaling the standard ones), so the tables in a file point at the software
that wrote it last. The database is built from encoders available on the
analyst's machine (``provlens qdb build``) plus samples the analyst adds from
their own phone, camera and platform downloads (``provlens qdb add``).

A match is weak evidence on its own: IJG libjpeg tables are shared by GIMP,
ImageMagick, Pillow, OpenCV, browsers and many web services. What it does
well is catch contradictions, such as a file whose EXIF says "Canon" but whose
tables are libjpeg quality 75.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from provlens.jpeg import STD_CHROMA, STD_LUMA, estimate_ijg_quality, ijg_table, parse

DB_PATH = Path(__file__).parent / "data" / "qtables.json"


@dataclass
class Match:
    source: str
    family: str
    quality: str
    distance: float
    exact: bool
    note: str = ""
    shared_with: list[str] = field(default_factory=list)  # other sources that write the identical tables

    def to_json(self) -> dict[str, Any]:
        return {"source": self.source, "family": self.family, "quality": self.quality,
                "distance": round(self.distance, 3), "exact": self.exact, "note": self.note,
                "shared_with": self.shared_with}


def _key(luma: list[int], chroma: list[int] | None) -> str:
    return ",".join(map(str, luma)) + "|" + (",".join(map(str, chroma)) if chroma else "")


def load_db(path: Path = DB_PATH) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))["entries"]


def _test_image():
    import numpy as np
    from PIL import Image

    rng = np.random.default_rng(7)
    y, x = np.mgrid[0:256, 0:256]
    base = (np.stack([x, y, (x + y) // 2], axis=-1) + rng.normal(0, 18, (256, 256, 3))).clip(0, 255)
    return Image.fromarray(base.astype("uint8"))


def _tables_of(data: bytes) -> tuple[list[int], list[int] | None]:
    info = parse(data)
    return info.luma or [], info.chroma


def build_db(path: Path = DB_PATH, extra: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Generate entries from every encoder this machine has. Deterministic for a given toolset."""
    from PIL import Image, JpegPresets

    img = _test_image()
    entries: list[dict[str, Any]] = []

    for q in range(1, 101):
        entries.append({"source": "IJG libjpeg standard tables", "family": "ijg",
                        "quality": f"q{q}", "luma": ijg_table(STD_LUMA, q), "chroma": ijg_table(STD_CHROMA, q),
                        "note": "libjpeg/libjpeg-turbo: GIMP, ImageMagick, Pillow, OpenCV, browsers, many web services"})

    for preset in JpegPresets.presets:
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=preset)
        luma, chroma = _tables_of(buf.getvalue())
        entries.append({"source": "Adobe Photoshop tables (via Pillow preset)", "family": "photoshop",
                        "quality": preset, "luma": luma, "chroma": chroma,
                        "note": "Pillow's presets reproduce Photoshop's quality settings"})

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src.png"
        img.save(src)
        if shutil.which("sips"):
            for q in range(0, 101, 5):
                out = Path(tmp) / f"sips{q}.jpg"
                subprocess.run(["sips", "-s", "format", "jpeg", "-s", "formatOptions", str(q), str(src), "--out", str(out)],
                               capture_output=True, check=False)
                if out.exists():
                    luma, chroma = _tables_of(out.read_bytes())
                    entries.append({"source": "Apple ImageIO (macOS/iOS encoder, via sips)", "family": "apple",
                                    "quality": f"{q}%", "luma": luma, "chroma": chroma,
                                    "note": "the encoder behind iPhone/macOS JPEG exports"})
        if shutil.which("ffmpeg"):
            for qv in range(2, 32):
                out = Path(tmp) / f"ff{qv}.jpg"
                subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(src), "-q:v", str(qv), str(out)],
                               capture_output=True, check=False)
                if out.exists():
                    luma, chroma = _tables_of(out.read_bytes())
                    entries.append({"source": "FFmpeg MJPEG encoder", "family": "ffmpeg", "quality": f"q:v {qv}",
                                    "luma": luma, "chroma": chroma,
                                    "note": "frame grabs and thumbnails produced with ffmpeg"})

        if shutil.which("cjpeg"):  # libjpeg-turbo's own CLI: confirms it writes the same IJG tables as Pillow
            src_ppm = Path(tmp) / "src.ppm"
            img.save(src_ppm)
            for q in range(5, 101, 5):
                out = Path(tmp) / f"cj{q}.jpg"
                subprocess.run(["cjpeg", "-quality", str(q), "-outfile", str(out), str(src_ppm)],
                               capture_output=True, check=False)
                if out.exists():
                    luma, chroma = _tables_of(out.read_bytes())
                    entries.append({"source": "libjpeg-turbo cjpeg", "family": "ijg", "quality": f"q{q}",
                                    "luma": luma, "chroma": chroma, "note": "the reference command-line encoder"})

    entries.extend(observed_entries())
    for e in extra or []:
        entries.append(e)
    # de-duplicate identical tables within a source
    seen, unique = set(), []
    for e in entries:
        k = (e["source"], _key(e["luma"], e.get("chroma")))
        if k not in seen:
            seen.add(k)
            unique.append(e)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"generated_by": "provlens qdb build", "entries": unique}
    path.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
    return unique


# Real devices and apps, observed in the pinned C2PA conformance samples (see datasets.py).
OBSERVED = {
    "nikon-20221019-building.jpeg": ("Nikon Z 9 in-camera JPEG (C2PA sample)", "camera"),
    "truepic-20230212-camera.jpg": ("Google Pixel 5 via Truepic Lens (C2PA sample)", "phone"),
    "adobe-20220124-A.jpg": ("Adobe Lightroom 5.3 export (C2PA sample)", "photoshop"),
}


def observed_entries(root: Path | None = None) -> list[dict[str, Any]]:
    """Tables read from real files in the C2PA sample cache (skipped when it was never fetched)."""
    from provlens import datasets

    out = []
    cache = datasets.cache_dir(root or Path.cwd())
    for name, (source, family) in OBSERVED.items():
        f = cache / name
        if f.exists() and datasets.blob_sha(f.read_bytes()) == datasets.FILES[name][0]:
            luma, chroma = _tables_of(f.read_bytes())
            out.append({"source": source, "family": family, "quality": "as observed", "luma": luma, "chroma": chroma,
                        "note": f"{datasets.REPO}@{datasets.COMMIT[:12]}/{name}"})
    return out


def add_sample(image: Path, source: str, family: str = "user", quality: str = "", path: Path = DB_PATH) -> dict[str, Any]:
    """Record the tables of a reference file (your phone, a platform download...)."""
    luma, chroma = _tables_of(Path(image).read_bytes())
    if not luma:
        raise ValueError(f"{image} has no quantisation tables")
    db = load_db(path)
    entry = {"source": source, "family": family, "quality": quality or "as captured", "luma": luma,
             "chroma": chroma, "note": f"added from {Path(image).name}"}
    db.append(entry)
    path.write_text(json.dumps({"generated_by": "provlens qdb", "entries": db}, separators=(",", ":")) + "\n")
    return entry


def match(luma: list[int], chroma: list[int] | None, db: list[dict[str, Any]] | None = None, top: int = 3) -> list[Match]:
    db = load_db() if db is None else db
    scored = []
    for e in db:
        d = sum(abs(a - b) for a, b in zip(e["luma"], luma)) / 64
        if chroma and e.get("chroma"):
            d = (d + sum(abs(a - b) for a, b in zip(e["chroma"], chroma)) / 64) / 2
        elif chroma and not e.get("chroma") or (e.get("chroma") and not chroma):
            d += 0.5
        scored.append((d, e))
    scored.sort(key=lambda t: t[0])
    # identical tables written by several sources collapse into one candidate that names them all
    groups: dict[str, list[tuple[float, dict[str, Any]]]] = {}
    for d, e in scored:
        groups.setdefault(_key(e["luma"], e.get("chroma")), []).append((d, e))
    out = []
    for members in groups.values():
        d, e = members[0]
        others = list(dict.fromkeys(f"{m['source']} {m['quality']}" for _, m in members[1:]))
        out.append(Match(e["source"], e["family"], e["quality"], d, d == 0, e.get("note", ""), others))
        if len(out) == top:
            break
    return out


def describe(luma: list[int], chroma: list[int] | None) -> dict[str, Any]:
    q, exact_ijg = estimate_ijg_quality(luma, chroma)
    matches = match(luma, chroma)
    best = matches[0] if matches else None
    return {
        "ijg_quality_estimate": q,
        "ijg_exact": exact_ijg,
        "best": best.to_json() if best else None,
        "candidates": [m.to_json() for m in matches],
        "custom_tables": not (best and best.exact),
    }
