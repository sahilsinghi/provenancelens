"""JPEG container structure: markers, quantisation tables, frame header.

Tables are returned in *natural* (row-major 8x8) order. In the file they are
stored in zig-zag order, and mixing the two up is the most common bug in
quantisation-table tooling.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

ZIGZAG = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
]
# JPEG Annex K example tables (natural order); IJG libjpeg scales these.
STD_LUMA = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
]
STD_CHROMA = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99,
] + [99] * 32

MARKER_NAMES = {
    0xC0: "SOF0 baseline", 0xC1: "SOF1 extended", 0xC2: "SOF2 progressive", 0xC4: "DHT", 0xDB: "DQT",
    0xDD: "DRI", 0xDA: "SOS", 0xFE: "COM", 0xE0: "APP0", 0xE1: "APP1", 0xE2: "APP2", 0xED: "APP13",
    0xEE: "APP14", 0xEB: "APP11",
}


@dataclass
class Segment:
    marker: int
    offset: int
    length: int
    payload: bytes

    @property
    def name(self) -> str:
        return MARKER_NAMES.get(self.marker, f"0x{self.marker:02X}")

    def kind(self) -> str:
        p = self.payload
        if self.marker == 0xE0 and p.startswith(b"JFIF\x00"):
            return "JFIF"
        if self.marker == 0xE0 and p.startswith(b"JFXX\x00"):
            return "JFXX thumbnail"
        if self.marker == 0xE1 and p.startswith(b"Exif\x00\x00"):
            return "Exif"
        if self.marker == 0xE1 and p.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
            return "XMP"
        if self.marker == 0xE1 and p.startswith(b"http://ns.adobe.com/xmp/extension/\x00"):
            return "XMP extension"
        if self.marker == 0xE2 and p.startswith(b"ICC_PROFILE\x00"):
            return "ICC profile"
        if self.marker == 0xE2 and p.startswith(b"MPF\x00"):
            return "MPF (multi-picture)"
        if self.marker == 0xEB and p[:2] == b"JP":
            return "JUMBF (C2PA)"
        if self.marker == 0xED and p.startswith(b"Photoshop 3.0\x00"):
            return "Photoshop IRB"
        if self.marker == 0xEE and p.startswith(b"Adobe"):
            return "Adobe"
        if self.marker == 0xFE:
            return "Comment"
        return self.name


@dataclass
class JpegInfo:
    segments: list[Segment] = field(default_factory=list)
    qtables: dict[int, list[int]] = field(default_factory=dict)  # natural order
    qtable_precision: dict[int, int] = field(default_factory=dict)
    component_tables: list[int] = field(default_factory=list)  # quant table per component
    sampling: list[tuple[int, int]] = field(default_factory=list)
    width: int = 0
    height: int = 0
    progressive: bool = False
    restart_interval: int = 0
    huffman_tables: int = 0
    comments: list[str] = field(default_factory=list)
    scan_offset: int = 0
    trailing_bytes: int = 0

    @property
    def luma(self) -> list[int] | None:
        if self.component_tables:
            return self.qtables.get(self.component_tables[0])
        return self.qtables.get(0)

    @property
    def chroma(self) -> list[int] | None:
        if len(self.component_tables) > 1:
            return self.qtables.get(self.component_tables[1])
        return self.qtables.get(1)

    @property
    def subsampling(self) -> str:
        if len(self.sampling) < 3:
            return "grayscale" if len(self.sampling) == 1 else "unknown"
        (h0, v0), (h1, v1) = self.sampling[0], self.sampling[1]
        if (h0, v0) == (h1, v1):
            return "4:4:4"
        if h0 == 2 * h1 and v0 == 2 * v1:
            return "4:2:0"
        if h0 == 2 * h1 and v0 == v1:
            return "4:2:2"
        return f"{h0}x{v0}/{h1}x{v1}"

    def app_kinds(self) -> list[str]:
        return [s.kind() for s in self.segments if 0xE0 <= s.marker <= 0xEF or s.marker == 0xFE]


class NotJpeg(ValueError):
    pass


def parse(data: bytes) -> JpegInfo:
    if data[:2] != b"\xff\xd8":
        raise NotJpeg("missing SOI marker")
    info = JpegInfo()
    i = 2
    n = len(data)
    while i < n:
        if data[i] != 0xFF:
            raise NotJpeg(f"expected a marker at offset {i}")
        while i < n and data[i] == 0xFF:
            i += 1
        marker = data[i]
        i += 1
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            continue
        if marker == 0xD9:
            break
        length = struct.unpack(">H", data[i:i + 2])[0]
        payload = data[i + 2:i + length]
        seg = Segment(marker, i - 2, length, payload)
        info.segments.append(seg)
        if marker == 0xDB:
            j = 0
            while j < len(payload):
                pq, tq = payload[j] >> 4, payload[j] & 0x0F
                j += 1
                if pq:
                    zz = list(struct.unpack(">64H", payload[j:j + 128]))
                    j += 128
                else:
                    zz = list(payload[j:j + 64])
                    j += 64
                natural = [0] * 64
                for k, pos in enumerate(ZIGZAG):
                    natural[pos] = zz[k]
                info.qtables[tq] = natural
                info.qtable_precision[tq] = 16 if pq else 8
        elif marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC9, 0xCA):
            info.progressive = marker in (0xC2, 0xCA)
            info.height, info.width = struct.unpack(">HH", payload[1:5])
            ncomp = payload[5]
            for c in range(ncomp):
                cid, hv, tq = payload[6 + 3 * c:9 + 3 * c]
                info.sampling.append((hv >> 4, hv & 0x0F))
                info.component_tables.append(tq)
        elif marker == 0xC4:
            j = 0
            while j < len(payload):
                counts = payload[j + 1:j + 17]
                j += 17 + sum(counts)
                info.huffman_tables += 1
        elif marker == 0xDD:
            info.restart_interval = struct.unpack(">H", payload[:2])[0]
        elif marker == 0xFE:
            info.comments.append(payload.decode("latin-1", "replace"))
        elif marker == 0xDA:
            info.scan_offset = i + length
            # skip entropy-coded data to the next real marker
            j = i + length
            while j < n - 1:
                if data[j] == 0xFF and data[j + 1] not in (0x00,) and not 0xD0 <= data[j + 1] <= 0xD7:
                    break
                j += 1
            i = j
            continue
        i += length
    eoi = data.rfind(b"\xff\xd9")
    if eoi != -1:
        info.trailing_bytes = len(data) - (eoi + 2)
    return info


def parse_file(path: Path) -> JpegInfo:
    return parse(Path(path).read_bytes())


# --------------------------------------------------------------------------
# quality estimation
# --------------------------------------------------------------------------

def ijg_table(base: list[int], quality: int) -> list[int]:
    quality = min(max(quality, 1), 100)
    scale = 5000 // quality if quality < 50 else 200 - quality * 2
    return [min(max((b * scale + 50) // 100, 1), 255) for b in base]


def estimate_ijg_quality(luma: list[int], chroma: list[int] | None = None) -> tuple[int, bool]:
    """Best IJG quality for these tables and whether they match that quality exactly."""
    best_q, best_err = 50, float("inf")
    for q in range(1, 101):
        err = sum(abs(a - b) for a, b in zip(ijg_table(STD_LUMA, q), luma))
        if chroma:
            err += sum(abs(a - b) for a, b in zip(ijg_table(STD_CHROMA, q), chroma))
        if err < best_err:
            best_q, best_err = q, err
    return best_q, best_err == 0


def mean_step(table: list[int]) -> float:
    return sum(table) / len(table)
