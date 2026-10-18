"""Build a labelled test set, fit/calibrate the detectors, and measure them honestly.

Source images are scikit-image's bundled photographs and textures, downscaled
2x with Lanczos so any earlier JPEG grid is destroyed, then cropped. Every
manipulation is generated here with a known ground truth:

* ``authentic``   one JPEG save at quality 75-95
* ``platform``    authentic, then resized to 80% and re-saved at 70-80 (a benign re-upload)
* ``double_up``   saved at q1, re-saved at a *higher* quality q2 (download, edit, export)
* ``double_down`` saved at q1, re-saved at a *lower* quality q2 (camera JPEG -> platform)
* ``splice``      a region from another photo (recompressed, noisier or resampled) pasted into a
                  downloaded JPEG, then exported at 85-95 - ground-truth box recorded
* ``ai_declared`` an image whose XMP declares IPTC DigitalSourceType trainedAlgorithmicMedia
* ``stripped``    a PNG with no metadata at all

Detectors are fitted / calibrated on some source images and measured on the
others (split by source, so no crop of a test image is ever seen in training).
"""

from __future__ import annotations

import io
import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

SOURCES = ["astronaut", "coffee", "chelsea", "rocket", "immunohistochemistry", "hubble_deep_field", "camera",
           "brick", "grass", "gravel", "coins", "moon", "page"]
TEST_SOURCES = {"coffee", "camera", "grass", "hubble_deep_field"}
DATA = Path(__file__).parent / "data"
XMP_AI = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
          b'<rdf:Description xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/" '
          b'Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"/>'
          b"</rdf:RDF></x:xmpmeta>")


@dataclass
class Item:
    path: Path
    kind: str
    source: str
    q1: int | None = None
    q2: int | None = None
    box: list[int] | None = None

    @property
    def manipulated(self) -> bool:
        return self.kind in ("splice",)

    def to_json(self) -> dict[str, Any]:
        return {"path": str(self.path), "kind": self.kind, "source": self.source, "q1": self.q1, "q2": self.q2, "box": self.box}


def _sources() -> dict[str, Image.Image]:
    from skimage import data

    out = {}
    for name in SOURCES:
        a = getattr(data, name)()
        if a.ndim == 2:
            a = np.stack([a] * 3, axis=-1)
        im = Image.fromarray(a[..., :3]).convert("RGB")
        out[name] = im.resize((im.width // 2, im.height // 2), Image.LANCZOS)
    return out


def _jpeg(im: Image.Image, q: int, **kw) -> bytes:
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=q, **kw)
    return buf.getvalue()


def _open(b: bytes) -> Image.Image:
    return Image.open(io.BytesIO(b)).convert("RGB")


def _crop(im: Image.Image, rng: random.Random, size: int = 320) -> Image.Image:
    w, h = min(im.width, size), min(im.height, size)
    x, y = rng.randint(0, im.width - w), rng.randint(0, im.height - h)
    return im.crop((x, y, x + w, y + h))


def generate(out: Path, per_source: int = 6, seed: int = 2026) -> list[Item]:
    rng = random.Random(seed)
    src = _sources()
    out.mkdir(parents=True, exist_ok=True)
    items: list[Item] = []
    names = list(src)
    for name in names:
        for i in range(per_source):
            base = _crop(src[name], rng)
            stem = f"{name}-{i}"
            q = rng.choice(range(75, 96, 5))
            p = out / f"{stem}-authentic.jpg"
            p.write_bytes(_jpeg(base, q))
            items.append(Item(p, "authentic", name, q2=q))

            first = _open(_jpeg(base, 92))
            small = first.resize((int(first.width * 0.8), int(first.height * 0.8)), Image.LANCZOS)
            q = rng.choice(range(70, 81, 5))
            p = out / f"{stem}-platform.jpg"
            p.write_bytes(_jpeg(small, q))
            items.append(Item(p, "platform", name, q1=92, q2=q))

            q1 = rng.choice(range(55, 81, 5))
            q2 = rng.choice([x for x in range(q1 + 10, 96, 5)] or [95])
            p = out / f"{stem}-double_up.jpg"
            p.write_bytes(_jpeg(_open(_jpeg(base, q1)), q2))
            items.append(Item(p, "double_up", name, q1, q2))

            q1 = rng.choice(range(85, 96, 5))
            q2 = rng.choice(range(60, q1 - 5, 5))
            p = out / f"{stem}-double_down.jpg"
            p.write_bytes(_jpeg(_open(_jpeg(base, q1)), q2))
            items.append(Item(p, "double_down", name, q1, q2))

            donor_name = rng.choice([n for n in names if n != name])
            bg = _open(_jpeg(base, rng.choice(range(65, 81, 5))))  # a downloaded JPEG
            w, h = rng.randint(bg.width // 4, bg.width // 3), rng.randint(bg.height // 4, bg.height // 3)
            x, y = rng.randint(0, bg.width - w), rng.randint(0, bg.height - h)
            donor = _crop(src[donor_name], rng, size=max(w, h) * 2).resize((w, h), Image.LANCZOS)
            how = rng.choice(["recompressed", "noisier", "resampled"])
            if how == "recompressed":
                donor = _open(_jpeg(donor, rng.choice(range(40, 61, 5))))
            elif how == "noisier":
                arr = np.asarray(donor, dtype=np.float64) + np.random.default_rng(rng.randint(0, 10**6)).normal(0, rng.uniform(4, 8), (h, w, 3))
                donor = Image.fromarray(arr.clip(0, 255).astype(np.uint8))
            else:
                donor = donor.resize((w // 2, h // 2), Image.BILINEAR).resize((w, h), Image.BICUBIC)
            bg.paste(donor, (x, y))
            q2 = rng.choice(range(85, 96, 5))
            p = out / f"{stem}-splice-{how}.jpg"
            p.write_bytes(_jpeg(bg, q2))
            items.append(Item(p, "splice", name, None, q2, [x, y, x + w, y + h]))

        base = _crop(src[name], rng)
        p = out / f"{name}-ai_declared.jpg"
        p.write_bytes(_jpeg(base, 90, xmp=XMP_AI))
        items.append(Item(p, "ai_declared", name, q2=90))
        p = out / f"{name}-stripped.png"
        base.save(p, "PNG")
        items.append(Item(p, "stripped", name))
    (out / "manifest.json").write_text(json.dumps([i.to_json() for i in items], indent=1))
    return items


# --------------------------------------------------------------------------

def _confusion(pairs: list[tuple[bool, bool]]) -> dict[str, int]:
    c = Counter((t, p) for t, p in pairs)
    return {"tp": c[(True, True)], "fn": c[(True, False)], "fp": c[(False, True)], "tn": c[(False, False)]}


def _rates(c: dict[str, int]) -> dict[str, float]:
    tp, fn, fp, tn = c["tp"], c["fn"], c["fp"], c["tn"]
    return {"recall": tp / (tp + fn) if tp + fn else 0.0, "specificity": tn / (tn + fp) if tn + fp else 0.0,
            "precision": tp / (tp + fp) if tp + fp else 0.0, "accuracy": (tp + tn) / max(1, tp + tn + fp + fn)}


def _overlap(a: list[int], b: list[int]) -> bool:
    return not (a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1])


def evaluate(items: list[Item], fit_models: bool = True) -> dict[str, Any]:
    from provlens import analyze, djpeg, pixel

    report: dict[str, Any] = {"items": Counter(i.kind for i in items), "test_sources": sorted(TEST_SOURCES)}
    train = [i for i in items if i.source not in TEST_SOURCES]
    test = [i for i in items if i.source in TEST_SOURCES]

    # ---- double JPEG --------------------------------------------------------
    # Train only on what the features can see: single saves and benign re-uploads
    # (negative) against a second save at higher quality (positive). A second save
    # at *lower* quality leaves almost no footprint; labelling it positive only
    # squashes every probability towards 0.5, so it is measured, not trained on.
    train_kinds = {"authentic": 0, "platform": 0, "double_up": 1}
    test_kinds = {"authentic": 0, "platform": 0, "double_up": 1, "double_down": 1, "splice": 1}
    feats = {}
    for it in items:
        if it.kind in test_kinds:
            feats[it.path] = djpeg.features_from_bytes(it.path.read_bytes())
    tr = [i for i in train if i.kind in train_kinds and feats[i.path]]
    X = np.array([[feats[i.path][k] for k in djpeg.FEATURES] for i in tr])
    y = np.array([train_kinds[i.kind] for i in tr], dtype=np.float64)
    model = djpeg.fit(X, y)
    # threshold: the score that at most 1% of training negatives reach, plus a 0.05
    # margin, kept within [0.2, 0.95]; the held-out sources then measure it honestly
    neg = sorted(djpeg.probability(feats[i.path], model) for i in tr if train_kinds[i.kind] == 0)
    model["threshold"] = round(min(0.95, max(0.2, float(np.quantile(neg, 0.99)) + 0.05)), 3)
    if fit_models:
        (DATA / "djpeg_model.json").write_text(json.dumps(model, indent=2) + "\n")
    by_kind: dict[str, list[bool]] = defaultdict(list)
    pairs = []
    for i in test:
        if i.kind in test_kinds and feats[i.path]:
            pred = djpeg.probability(feats[i.path], model) >= model["threshold"]
            by_kind[i.kind].append(pred)
            if i.kind != "splice":
                pairs.append((bool(test_kinds[i.kind]), pred))
    report["djpeg"] = {
        "confusion": _confusion(pairs), "rates": _rates(_confusion(pairs)),
        "flagged_share_by_kind": {k: round(sum(v) / len(v), 3) for k, v in sorted(by_kind.items())},
        "threshold": model["threshold"], "model": model,
    }

    # ---- pixel maps: calibrate on authentic training images -----------------
    def map_scores(it: Item) -> dict[str, tuple[float, list[int] | None]]:
        img = Image.open(it.path).convert("RGB")
        out = {}
        q = None
        if it.path.suffix == ".jpg":
            from provlens.jpeg import estimate_ijg_quality, parse

            info = parse(it.path.read_bytes())
            q = estimate_ijg_quality(info.luma, info.chroma)[0]
        for name, m in pixel.all_maps(img, q).items():
            top = m.regions[0] if m.regions else None
            out[name] = (top["mean_z"] if top else 0.0, top["bbox"] if top else None)
        return out

    scores = {it.path: map_scores(it) for it in items if it.kind in ("authentic", "platform", "splice")}
    thresholds = {}
    for name in ("ela", "noise", "ghost"):
        benign = sorted(scores[i.path][name][0] for i in train if i.kind in ("authentic", "platform"))
        floor = 3.5 if name == "ela" else 3.0  # the region detector's own z cut-off
        thresholds[name] = max(float(np.percentile(benign, 95)), floor) if benign else 99.0
    if fit_models:
        (DATA / "pixel_thresholds.json").write_text(json.dumps(thresholds, indent=2) + "\n")
    px = {}
    for name in ("ela", "noise", "ghost"):
        t = thresholds[name]
        fp = [scores[i.path][name][0] > t for i in test if i.kind in ("authentic", "platform")]
        hits = []
        for i in test:
            if i.kind == "splice":
                s, box = scores[i.path][name]
                hits.append(s > t and box is not None and _overlap(box, i.box))
        px[name] = {"threshold_z": round(t, 2), "false_alarm_rate": round(sum(fp) / max(1, len(fp)), 3),
                    "splice_localised_rate": round(sum(hits) / max(1, len(hits)), 3)}
    report["pixel"] = px

    # ---- whole pipeline verdicts on the held-out sources --------------------
    from provlens import evidence

    evidence.pixel_thresholds.cache_clear()  # use the thresholds written above
    rows = []
    for i in test:
        r = analyze.analyse(i.path, maps=True)
        v = r["verdict"]
        rows.append({"kind": i.kind, "level": v["editing_level"], "generation": v["generation_score"] >= 0.5,
                     "limited": v["limited_signal"], "score": v["editing_score"]})
    matrix: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        matrix[r["kind"]][r["level"]] += 1
    report["verdicts"] = {
        "matrix": {k: dict(v) for k, v in matrix.items()},
        "ai_declared_recognised": f"{sum(r['generation'] for r in rows if r['kind'] == 'ai_declared')}/"
                                  f"{sum(1 for r in rows if r['kind'] == 'ai_declared')}",
        "stripped_limited_signal": f"{sum(r['limited'] for r in rows if r['kind'] == 'stripped')}/"
                                   f"{sum(1 for r in rows if r['kind'] == 'stripped')}",
        "binary": _rates(_confusion([(r["kind"] in ("splice",), r["level"] in ("moderate", "strong"))
                                     for r in rows if r["kind"] in ("authentic", "platform", "splice")])),
        "binary_confusion": _confusion([(r["kind"] in ("splice",), r["level"] in ("moderate", "strong"))
                                        for r in rows if r["kind"] in ("authentic", "platform", "splice")]),
    }
    return report
