#!/usr/bin/env python3
"""Build the sample reports in docs/samples/ from scratch.

    python scripts/make_samples.py [docs/samples]

Every input is generated here from scikit-image's public-domain / CC0 photographs,
so the samples can be rebuilt bit-for-bit in meaning (signatures and timestamps
differ per run). A fresh throwaway signing identity is created each time; its
root certificate is written next to the samples so the signed card can be
checked with `provlens analyze docs/samples/edited.card.png --trust docs/samples/test-root.pem`.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provlens import card, report, testsign  # noqa: E402
from provlens.analyze import analyse  # noqa: E402
from provlens.cli import _strip_images  # noqa: E402

AI_SOURCE = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"


def _img(name: str) -> Image.Image:
    from skimage import data

    a = getattr(data, name)()
    if a.ndim == 2:
        a = np.stack([a] * 3, axis=-1)
    return Image.fromarray(a[..., :3]).convert("RGB")


def _jpg(im: Image.Image, q: int) -> bytes:
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=q)
    return buf.getvalue()


def _open(b: bytes) -> Image.Image:
    return Image.open(io.BytesIO(b)).convert("RGB")


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "samples"
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="provlens-samples-"))
    ident = testsign.make_identity(work / "id", "ProvenanceLens Sample Camera")
    shutil.copy(ident.root_pem, out / "test-root.pem")
    inputs: dict[str, tuple[Path, str]] = {}

    # 1. genuine: one camera-style save, signed at capture
    raw = work / "astronaut.jpg"
    raw.write_bytes(_jpg(_img("astronaut"), 90))
    inputs["genuine"] = (testsign.sign(raw, work / "genuine.jpg", ident, title="astronaut.jpg"),
                         "Signed at capture with a test identity; analysed with that identity's root as a trust anchor.")

    # 2. edited: a patch from another JPEG pasted into a downloaded JPEG, exported again
    bg = _open(_jpg(_img("astronaut"), 70))
    bg.paste(_open(_jpg(_img("chelsea").crop((150, 40, 330, 220)), 45)), (300, 60))
    (work / "edited.jpg").write_bytes(_jpg(bg, 90))
    inputs["edited"] = (work / "edited.jpg", "A 180x180 patch from another JPEG pasted at (300, 60), then re-exported. No credentials.")

    # 3. tampered: the signed genuine image with one byte of scan data flipped
    data = bytearray(inputs["genuine"][0].read_bytes())
    data[len(data) - 4000] ^= 0x01
    (work / "tampered.jpg").write_bytes(bytes(data))
    inputs["tampered"] = (work / "tampered.jpg", "The signed genuine image with a single bit flipped in the compressed pixel data.")

    # 4. ai-labelled: credentials that declare generative-AI origin
    src = work / "coffee.jpg"
    src.write_bytes(_jpg(_img("coffee"), 90))
    inputs["ai-labelled"] = (
        testsign.sign(src, work / "ai-labelled.jpg", ident, title="coffee.jpg",
                      actions=[{"action": "c2pa.created", "digitalSourceType": AI_SOURCE,
                                "softwareAgent": {"name": "Example Image Model 3"}}]),
        "Credentials declare trainedAlgorithmicMedia. (The pixels are a public-domain photo: what is under test is "
        "that a declared label is found and shown, not a guess from pixels.)")

    # 5. stripped: a PNG with no metadata at all
    _img("rocket").save(work / "stripped.png")
    inputs["stripped"] = (work / "stripped.png", "A PNG with no metadata, no credentials and no JPEG history.")

    index = []
    for name, (path, how) in inputs.items():
        r = analyse(path, [ident.root_pem])
        r["file"]["name"] = f"{name}{path.suffix}"
        (out / f"{name}.html").write_text(report.render_html(r), encoding="utf-8")
        (out / f"{name}.json").write_text(json.dumps(_strip_images(r), indent=1))
        card.write(r, out / f"{name}.card.png", analysed=path,
                   identity_dir=ident.root_pem.parent if name == "edited" else None)
        index.append({"name": name, "how": how, "c2pa": r["c2pa"]["state"], "editing": r["verdict"]["editing_level"],
                      "generation": r["verdict"]["generation_score"] >= 0.5, "headline": r["verdict"]["headline"]})
        print(f"{name:12} {r['c2pa']['state']:8} editing={r['verdict']['editing_level']:9} {r['verdict']['headline'][:110]}")
    (out / "index.json").write_text(json.dumps(index, indent=1))
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
