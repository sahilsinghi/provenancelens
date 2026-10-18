"""Damaged, truncated and oversized files must produce a report, never a crash or a memory blow-up."""

from __future__ import annotations

import struct
import zlib

import pytest

from provlens import analyze, report
from provlens.analyze import analyse

from .conftest import jpg


def _assert_reports(r):
    assert r["verdict"] is not None
    page = report.render_html(r)
    assert "ProvenanceLens report" in page
    return page


def test_truncated_jpeg(tmp_path, photos):
    data = jpg(photos["coffee"], 90)
    p = tmp_path / "cut.jpg"
    p.write_bytes(data[: len(data) // 2])
    r = analyse(p)
    _assert_reports(r)
    assert "error" in r["image"] or r.get("pixel")  # Pillow may or may not be able to show a partial image


def test_broken_segment_length(tmp_path, photos):
    data = bytearray(jpg(photos["coffee"], 90))
    i = data.find(b"\xff\xdb")
    data[i + 2:i + 4] = b"\x00\x05"  # DQT claims 3 bytes of payload
    p = tmp_path / "dqt.jpg"
    p.write_bytes(bytes(data))
    r = analyse(p)
    page = _assert_reports(r)
    assert r["jpeg_error"].startswith(("malformed", "expected"))
    assert any(s["id"] == "jpeg.malformed" for s in r["verdict"]["signals"])
    assert "could not be parsed" in page


def _png_header_only(width: int, height: int) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\0" * 1000)) + chunk(b"IEND", b"")


@pytest.mark.parametrize("side", [12_000, 40_000])  # 144 MP (over our limit) and 1.6 GP (over Pillow's)
def test_decompression_bomb_is_not_decoded(tmp_path, side):
    p = tmp_path / "bomb.png"
    p.write_bytes(_png_header_only(side, side))
    assert p.stat().st_size < 2000
    r = analyse(p)
    _assert_reports(r)
    assert "pixel" not in r
    assert "error" in r["image"]
    assert any(s["id"] == "image.decode" for s in r["verdict"]["signals"])


def test_large_images_skip_maps_and_say_so(tmp_path, photos, monkeypatch):
    monkeypatch.setattr(analyze, "MAX_MAP_PIXELS", 10_000)
    p = tmp_path / "big.jpg"
    p.write_bytes(jpg(photos["coffee"], 90))
    r = analyse(p)
    _assert_reports(r)
    assert "pixel" not in r and "maps_skipped" in r["image"]
    assert r["jpeg"]["djpeg"]["applicable"] is False and "limit" in r["jpeg"]["djpeg"]["note"]
    assert any(s["id"] == "image.maps_skipped" for s in r["verdict"]["signals"])


def test_xmp_entities_are_never_expanded():
    from provlens.metadata import _parse_xmp

    xxe = (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
           b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><a>&e;</a></x:xmpmeta>')
    props, _ = _parse_xmp(xxe)
    assert "root:" not in str(props)
    lol = (b'<!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
           b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><x:xmpmeta xmlns:x="adobe:ns:meta/">&c;</x:xmpmeta>')
    props, _ = _parse_xmp(lol)
    assert "aaaaaaaaaa" not in str(props)
