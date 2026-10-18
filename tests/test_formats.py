from __future__ import annotations

import pytest

from provlens import jumbf, qtables
from provlens.jpeg import STD_CHROMA, STD_LUMA, ZIGZAG, NotJpeg, estimate_ijg_quality, ijg_table, parse
from provlens.sniff import extension_mismatch, sniff

from .conftest import jpg


@pytest.mark.parametrize("q", [10, 50, 75, 90, 95, 100])
def test_pillow_writes_ijg_tables_in_natural_order(photos, q):
    info = parse(jpg(photos["coffee"], q))
    assert info.luma == ijg_table(STD_LUMA, q)
    assert info.chroma == ijg_table(STD_CHROMA, q)
    assert estimate_ijg_quality(info.luma, info.chroma) == (q, True)


def test_zigzag_is_a_permutation():
    assert sorted(ZIGZAG) == list(range(64))


def test_parse_reports_structure(photos):
    info = parse(jpg(photos["coffee"], 80, subsampling=2, progressive=True))
    assert info.progressive and info.subsampling == "4:2:0"
    assert info.width == photos["coffee"].width and info.trailing_bytes == 0
    data = jpg(photos["coffee"], 80) + b"PK\x03\x04 hidden zip"
    assert parse(data).trailing_bytes == 15


def test_not_a_jpeg():
    with pytest.raises(NotJpeg):
        parse(b"\x89PNG\r\n\x1a\n" + b"\0" * 32)


def test_qtable_match_prefers_exact_and_ranks_neighbours(photos):
    info = parse(jpg(photos["coffee"], 83))
    d = qtables.describe(info.luma, info.chroma)
    assert d["best"]["family"] == "ijg" and d["best"]["quality"] == "q83" and d["best"]["exact"]
    assert d["candidates"][1]["distance"] > 0


def test_qdb_add_sample(tmp_path, photos):
    db = tmp_path / "q.json"
    db.write_text('{"entries": []}')
    custom = [min(255, v * 2 + 1) for v in STD_LUMA]
    # write a JPEG with a custom table through Pillow's qtables argument
    import io

    buf = io.BytesIO()
    photos["coffee"].save(buf, "JPEG", qtables=[custom, STD_CHROMA])
    img = tmp_path / "custom.jpg"
    img.write_bytes(buf.getvalue())
    qtables.add_sample(img, "My scanner", path=db)
    found = qtables.match(custom, STD_CHROMA, db=qtables.load_db(db))
    assert found[0].source == "My scanner" and found[0].distance == 0


def test_sniff_and_extension_mismatch(tmp_path, photos):
    p = tmp_path / "photo.png"
    p.write_bytes(jpg(photos["coffee"], 80))
    assert sniff(p) == "image/jpeg"
    assert "jpeg" in (extension_mismatch(p, "image/jpeg") or "").lower()
    ok = tmp_path / "photo.jpg"
    ok.write_bytes(jpg(photos["coffee"], 80))
    assert extension_mismatch(ok, "image/jpeg") is None


@pytest.mark.parametrize("encoded,value", [
    (bytes.fromhex("00"), 0), (bytes.fromhex("1903e8"), 1000), (bytes.fromhex("3863"), -100),
    (bytes.fromhex("6449455446"), "IETF"), (bytes.fromhex("83010203"), [1, 2, 3]),
    (bytes.fromhex("a201020304"), {1: 2, 3: 4}), (bytes.fromhex("f5"), True), (bytes.fromhex("f6"), None),
    (bytes.fromhex("4401020304"), b"\x01\x02\x03\x04"),
])
def test_cbor_rfc8949_vectors(encoded, value):
    assert jumbf.cbor_decode(encoded) == value


def test_cbor_rejects_truncated():
    with pytest.raises(jumbf.CBORError):
        jumbf.cbor_decode(bytes.fromhex("1903"))
