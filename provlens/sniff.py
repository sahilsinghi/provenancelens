"""Identify a file by its magic bytes, never by its extension."""

from __future__ import annotations

from pathlib import Path

SIGNATURES = [
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"GIF87a", 0, "image/gif"),
    (b"GIF89a", 0, "image/gif"),
    (b"II*\x00", 0, "image/tiff"),
    (b"MM\x00*", 0, "image/tiff"),
    (b"BM", 0, "image/bmp"),
]
FTYP_BRANDS = {
    b"heic": "image/heic", b"heix": "image/heic", b"mif1": "image/heif", b"msf1": "image/heif",
    b"avif": "image/avif", b"isom": "video/mp4", b"mp41": "video/mp4", b"mp42": "video/mp4",
    b"qt  ": "video/quicktime", b"M4V ": "video/mp4", b"crx ": "image/x-canon-cr3",
    b"iso2": "video/mp4", b"iso5": "video/mp4", b"iso6": "video/mp4", b"avc1": "video/mp4", b"dash": "video/mp4",
}


def sniff(path: Path) -> str:
    with open(path, "rb") as fh:
        head = fh.read(64)
    for magic, offset, mime in SIGNATURES:
        if head[offset:offset + len(magic)] == magic:
            return mime
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[4:8] == b"ftyp":
        return FTYP_BRANDS.get(head[8:12], "application/iso-bmff")
    return "application/octet-stream"


def extension_mismatch(path: Path, mime: str) -> str | None:
    expected = {
        "image/jpeg": {".jpg", ".jpeg", ".jpe", ".jfif"}, "image/png": {".png"}, "image/webp": {".webp"},
        "image/gif": {".gif"}, "image/tiff": {".tif", ".tiff", ".dng"}, "image/heic": {".heic", ".heif"},
        "image/avif": {".avif"}, "video/mp4": {".mp4", ".m4v"}, "video/quicktime": {".mov", ".qt"},
    }.get(mime)
    if expected and path.suffix.lower() not in expected:
        return f"file content is {mime} but the extension is '{path.suffix}'"
    return None
