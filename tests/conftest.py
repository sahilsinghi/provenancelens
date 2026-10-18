from __future__ import annotations

import io
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]


def jpg(im: Image.Image, q: int, **kw) -> bytes:
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=q, **kw)
    return buf.getvalue()


def reopen(data: bytes) -> Image.Image:
    return Image.open(io.BytesIO(data)).convert("RGB")


def _half(a: np.ndarray) -> Image.Image:
    if a.ndim == 2:
        a = np.stack([a] * 3, axis=-1)
    im = Image.fromarray(a[..., :3]).convert("RGB")
    return im.resize((im.width // 2, im.height // 2), Image.LANCZOS)


@pytest.fixture(scope="session")
def photos() -> dict[str, Image.Image]:
    """Real photographs bundled with scikit-image, downscaled so no earlier JPEG grid survives."""
    data = pytest.importorskip("skimage.data")
    return {name: _half(getattr(data, name)()) for name in ("astronaut", "chelsea", "coffee", "rocket")}


@pytest.fixture(scope="session")
def identity(tmp_path_factory):
    from provlens import testsign

    return testsign.make_identity(tmp_path_factory.mktemp("identity"))


@pytest.fixture(scope="session")
def public_samples() -> Path:
    """The pinned C2PA conformance samples (fetched once into .cache/, hashes verified)."""
    from provlens import datasets

    try:
        datasets.fetch(ROOT)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"public C2PA samples unavailable ({exc}); run `provlens datasets fetch` with network access")
    return datasets.cache_dir(ROOT)
