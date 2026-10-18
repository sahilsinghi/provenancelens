"""Aligned double-JPEG detection with calibrated DCT statistics.

Re-saving a JPEG with a different quantisation table leaves a footprint of
the first compression in the second one's DCT coefficients: some bins are
emptied, others over-filled, and the leading-digit statistics shift.

The coefficients are recovered from the decoded luma plane (an 8x8
orthonormal DCT equals the JPEG FDCT), divided by the file's own luma table.
To know what a *single* compression of this content would look like, the
same statistics are computed on a copy shifted by 4 pixels (Fridrich's
calibration: off-grid blocks carry no quantisation footprint). The
features compare the two:

* ``dist_low`` / ``dist_high`` - L1 distance between observed and calibrated
  histograms for the first 10 / next 10 AC frequencies
* ``dist_max``  - the worst single frequency
* ``missing``   - share of bins that the calibration expects but are (nearly) empty
* ``benford``   - shift in the first-digit distribution of non-zero coefficients

A five-weight logistic model over standardised features (fitted by
``provlens evaluate``, stored in ``data/djpeg_model.json``) turns them into a
probability.

Measured blind spot (docs/evaluation.md): detection is reliable when the
second save used *finer* quantisation than the first, and nearly blind when
it was *coarser* - the common case of a camera JPEG recompressed by a
platform. Resizing or cropping between saves (non-aligned) also hides it.
"""

from __future__ import annotations

import io
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image
from scipy.fft import dctn

from provlens.jpeg import ZIGZAG, parse

MODEL_PATH = Path(__file__).parent / "data" / "djpeg_model.json"
FEATURES = ["dist_low", "dist_max", "dist_high", "missing", "benford"]
K = 12


@dataclass
class DJpegResult:
    applicable: bool
    probability: float | None = None
    double: bool | None = None
    features: dict[str, float] = field(default_factory=dict)
    note: str = ""
    threshold: float | None = None

    def to_json(self) -> dict[str, Any]:
        return {"applicable": self.applicable,
                "probability": None if self.probability is None else round(self.probability, 3),
                "threshold": self.threshold,
                "double": self.double, "features": {k: round(v, 4) for k, v in self.features.items()}, "note": self.note}


def _luma(data: bytes) -> np.ndarray:
    img = Image.open(io.BytesIO(data))
    img.draft("YCbCr", img.size)  # libjpeg's own YCbCr output, no RGB round trip
    y = np.asarray(img, dtype=np.float64)
    if y.ndim == 3:
        y = y[..., 0] if img.mode == "YCbCr" else np.asarray(img.convert("YCbCr"), dtype=np.float64)[..., 0]
    return y


def _block_dct(y: np.ndarray) -> np.ndarray:
    h, w = y.shape[0] // 8 * 8, y.shape[1] // 8 * 8
    b = (y[:h, :w] - 128.0).reshape(h // 8, 8, w // 8, 8).transpose(0, 2, 1, 3)
    return dctn(b, type=2, axes=(2, 3), norm="ortho").reshape(-1, 64)


def _first_digits(k: np.ndarray) -> np.ndarray:
    k = np.abs(k[k != 0]).astype(np.float64)
    if len(k) == 0:
        return np.zeros(9)
    d = (k / 10 ** np.floor(np.log10(k))).astype(int)
    h = np.bincount(d, minlength=10)[1:10].astype(np.float64)
    return h / h.sum()


def features_from_bytes(data: bytes) -> dict[str, float] | None:
    info = parse(data)
    if not info.luma:
        return None
    q = np.array(info.luma, dtype=np.float64)
    y = _luma(data)
    if y.shape[0] < 64 or y.shape[1] < 64:
        return None
    obs = _block_dct(y) / q
    cal = _block_dct(y[4:, 4:]) / q
    dists, missing, ko_all, kc_all = [], [], [], []
    for z in range(1, 21):
        p = ZIGZAG[z]
        ko = np.rint(obs[:, p]).astype(int)
        kc = np.rint(cal[:, p]).astype(int)
        ho = np.bincount(np.clip(ko, -K, K) + K, minlength=2 * K + 1).astype(np.float64)[1:-1]
        hc = np.bincount(np.clip(kc, -K, K) + K, minlength=2 * K + 1).astype(np.float64)[1:-1]
        ho /= ho.sum()
        hc /= hc.sum()
        keep = np.ones_like(ho, bool)
        keep[K - 1] = False  # the zero bin says little
        dists.append(float(np.abs(ho[keep] - hc[keep]).sum()))
        expected = hc[keep] > 0.005
        missing.append(float(((ho[keep] < 0.15 * hc[keep]) & expected).sum()) / max(1, int(expected.sum())))
        ko_all.append(ko)
        kc_all.append(kc)
    benford = float(np.abs(_first_digits(np.concatenate(ko_all)) - _first_digits(np.concatenate(kc_all))).sum())
    return {"dist_low": float(np.mean(dists[:10])), "dist_max": float(np.max(dists)),
            "dist_high": float(np.mean(dists[10:])), "missing": float(np.mean(missing)), "benford": benford}


def load_model(path: Path = MODEL_PATH) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def probability(feats: dict[str, float], model: dict[str, Any]) -> float:
    x = model["bias"]
    for name in FEATURES:
        x += model["weights"][name] * (feats[name] - model["mean"][name]) / model["std"][name]
    return 1 / (1 + math.exp(-x))


def detect(path_or_bytes: Path | bytes, model: dict[str, Any] | None = None) -> DJpegResult:
    data = path_or_bytes if isinstance(path_or_bytes, bytes) else Path(path_or_bytes).read_bytes()
    if data[:2] != b"\xff\xd8":
        return DJpegResult(False, note="not a JPEG: double-compression analysis does not apply")
    info = parse(data)
    if info.luma and max(info.luma[1:20]) <= 1:
        return DJpegResult(False, note="quality-100 tables: no requantisation footprint is possible")
    feats = features_from_bytes(data)
    if feats is None:
        return DJpegResult(False, note="image too small for coefficient statistics")
    model = model or load_model()
    if model is None:
        return DJpegResult(False, features=feats, note="no fitted model (run `provlens evaluate --fit`)")
    p = probability(feats, model)
    t = float(model.get("threshold", 0.5))
    res = DJpegResult(True, p, p >= t, feats, threshold=t)
    res.note = ("DCT statistics show a requantisation footprint: the JPEG was saved at least twice, the last time "
                "with finer quantisation than before" if res.double else
                "no double-compression footprint; note this test cannot see a second save at *lower* quality")
    return res


def fit(X: np.ndarray, y: np.ndarray, l2: float = 0.01, iters: int = 6000) -> dict[str, Any]:
    """Plain gradient-descent logistic regression on standardised features (transparent, five weights)."""
    mean, std = X.mean(axis=0), X.std(axis=0) + 1e-9
    Xs = (X - mean) / std
    A = np.hstack([np.ones((len(Xs), 1)), Xs])
    w = np.zeros(A.shape[1])
    for _ in range(iters):
        p = 1 / (1 + np.exp(-A @ w))
        g = A.T @ (p - y) / len(y) + l2 * np.r_[0, w[1:]]
        w -= 0.5 * g
    return {"features": FEATURES, "bias": float(w[0]), "weights": dict(zip(FEATURES, map(float, w[1:]))),
            "mean": dict(zip(FEATURES, map(float, mean))), "std": dict(zip(FEATURES, map(float, std))), "threshold": 0.5}
