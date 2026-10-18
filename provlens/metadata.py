"""EXIF / XMP / IPTC / PNG-text extraction and internal-consistency rules.

ExifTool (via ``exiftool -json``) is used when installed because it reads
every vendor format; otherwise Pillow plus a small TIFF walker (for the EXIF
thumbnail, which Pillow does not expose) covers JPEG, PNG, WebP and TIFF.

Each rule looks for a *contradiction* inside the file's own metadata, or a
declaration (editor software, AI source type). Metadata is trivially
editable, so a clean result proves nothing. A contradiction says the file is
not what it presents itself as.
"""

from __future__ import annotations

import io
import json
import re
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from PIL import ExifTags, Image, IptcImagePlugin

EDITORS = [
    "photoshop", "lightroom", "gimp", "snapseed", "picsart", "canva", "pixelmator", "affinity", "paint.net",
    "facetune", "meitu", "fotor", "luminar", "photopea", "adobe express", "darktable", "rawtherapee",
    "capture one", "photoscape", "inpixio", "remini", "lensa", "picmonkey", "befunky", "photodirector",
]
GENERATORS = ["midjourney", "dall-e", "dall·e", "dalle", "stable diffusion", "stablediffusion", "novelai", "firefly",
              "imagen", "leonardo", "ideogram", "flux", "comfyui", "automatic1111", "invokeai", "bing image creator",
              "microsoft designer", "gemini", "openai"]
MAX_PREVIEW_PIXELS = 120_000_000  # matches analyze.MAX_DECODE_PIXELS
CAMERA_MAKERNOTE_BRANDS = ["canon", "nikon", "sony", "fujifilm", "olympus", "om digital", "panasonic", "pentax",
                           "ricoh", "leica", "apple", "samsung"]
AI_DST = {
    "trainedalgorithmicmedia": "created by a trained AI model (generative AI)",
    "compositewithtrainedalgorithmicmedia": "composite that includes generative-AI content",
    "algorithmicmedia": "algorithmically generated",
    "compositesynthetic": "composite including synthetic elements",
}
NS = {
    "x": "adobe:ns:meta/", "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "xmp": "http://ns.adobe.com/xap/1.0/", "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
    "stEvt": "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#", "photoshop": "http://ns.adobe.com/photoshop/1.0/",
    "Iptc4xmpExt": "http://iptc.org/std/Iptc4xmpExt/2008-02-29/", "crs": "http://ns.adobe.com/camera-raw-settings/1.0/",
    "tiff": "http://ns.adobe.com/tiff/1.0/", "exif": "http://ns.adobe.com/exif/1.0/", "dc": "http://purl.org/dc/elements/1.1/",
}


@dataclass
class Finding:
    rule: str
    title: str
    status: str  # edited | generated | inconsistent | consistent | info | not_applicable
    strength: float  # 0..1 how strongly the observation supports its status
    detail: str

    def to_json(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class Metadata:
    exif: dict[str, Any] = field(default_factory=dict)
    gps: dict[str, Any] = field(default_factory=dict)
    xmp: dict[str, Any] = field(default_factory=dict)
    xmp_history: list[dict[str, str]] = field(default_factory=list)
    iptc: dict[str, Any] = field(default_factory=dict)
    png_text: dict[str, str] = field(default_factory=dict)
    thumbnail: bytes | None = None
    has_makernote: bool = False
    exiftool: dict[str, Any] | None = None
    width: int = 0
    height: int = 0

    @property
    def empty(self) -> bool:
        return not (self.exif or self.xmp or self.iptc or self.png_text or self.gps)

    def summary(self) -> dict[str, Any]:
        keep = ("Make", "Model", "Software", "DateTimeOriginal", "DateTime", "OffsetTimeOriginal", "LensModel",
                "ExposureTime", "FNumber", "ISOSpeedRatings", "ExifImageWidth", "ExifImageHeight", "Orientation", "Artist")
        return {
            "exif": {k: _plain(self.exif[k]) for k in keep if k in self.exif},
            "gps": {k: _plain(v) for k, v in self.gps.items() if k in ("GPSLatitude", "GPSLongitude", "GPSDateStamp", "GPSTimeStamp")},
            "xmp": {k: v for k, v in self.xmp.items() if not isinstance(v, (list, dict))},
            "xmp_history": self.xmp_history[:10],
            "iptc": {k: _plain(v) for k, v in self.iptc.items()},
            "png_text_keys": list(self.png_text),
            "thumbnail_bytes": len(self.thumbnail) if self.thumbnail else 0,
            "makernote": self.has_makernote,
            "reader": "exiftool + Pillow" if self.exiftool else "Pillow",
        }


def _plain(v: Any) -> Any:
    if isinstance(v, bytes):
        return v.decode("latin-1", "replace").strip("\x00")[:200]
    if isinstance(v, tuple):
        return [_plain(x) for x in v]
    try:
        json.dumps(v)
        return v
    except TypeError:
        return str(v)


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------

def _ifd1_thumbnail(exif_raw: bytes) -> bytes | None:
    """Walk TIFF IFD0 -> IFD1 and return the embedded JPEG thumbnail."""
    data = exif_raw[6:] if exif_raw.startswith(b"Exif\x00\x00") else exif_raw
    if len(data) < 8:
        return None
    endian = "<" if data[:2] == b"II" else ">"
    try:
        ifd0 = struct.unpack(endian + "I", data[4:8])[0]
        n = struct.unpack(endian + "H", data[ifd0:ifd0 + 2])[0]
        ifd1 = struct.unpack(endian + "I", data[ifd0 + 2 + 12 * n: ifd0 + 6 + 12 * n])[0]
        if not ifd1:
            return None
        n1 = struct.unpack(endian + "H", data[ifd1:ifd1 + 2])[0]
        off = length = None
        for k in range(n1):
            e = data[ifd1 + 2 + 12 * k: ifd1 + 14 + 12 * k]
            tag, typ, cnt = struct.unpack(endian + "HHI", e[:8])
            val = struct.unpack(endian + "I", e[8:12])[0]
            if tag == 0x0201:
                off = val
            elif tag == 0x0202:
                length = val
        if off and length and off + length <= len(data):
            thumb = data[off:off + length]
            return thumb if thumb[:2] == b"\xff\xd8" else None
    except struct.error:
        return None
    return None


def _parse_xmp(raw: bytes | str) -> tuple[dict[str, Any], list[dict[str, str]]]:
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    start = text.find("<x:xmpmeta")
    if start == -1:
        start = text.find("<rdf:RDF")
    end = max(text.rfind("</x:xmpmeta>") + len("</x:xmpmeta>"), text.rfind("</rdf:RDF>") + len("</rdf:RDF>"))
    if start == -1 or end <= start:
        return {}, []
    try:
        # nosec B314: parsing starts at <x:xmpmeta>, so no DOCTYPE/entity declarations reach expat
        # (tests/test_hostile_inputs.py::test_xmp_entities_are_never_expanded)
        root = ET.fromstring(text[start:end])  # nosec B314
    except ET.ParseError:
        return {"_unparseable": True}, []
    props: dict[str, Any] = {}
    rev = {v: k for k, v in NS.items()}
    for desc in root.iter(f"{{{NS['rdf']}}}Description"):
        for attr, value in desc.attrib.items():
            if attr.startswith("{"):
                uri, local = attr[1:].split("}", 1)
                if uri in rev:
                    props[f"{rev[uri]}:{local}"] = value
        for child in desc:
            if not child.tag.startswith("{"):
                continue
            uri, local = child.tag[1:].split("}", 1)
            if uri not in rev:
                continue
            key = f"{rev[uri]}:{local}"
            if key == "xmpMM:History":
                continue
            items = [li.text for li in child.iter(f"{{{NS['rdf']}}}li") if li.text]
            props[key] = items if items else (child.text or "").strip()
    history = []
    for li in root.iter(f"{{{NS['rdf']}}}li"):
        ev = {}
        for attr, value in li.attrib.items():
            if attr.startswith(f"{{{NS['stEvt']}}}"):
                ev[attr.split("}", 1)[1]] = value
        for child in li:
            if child.tag.startswith(f"{{{NS['stEvt']}}}"):
                ev[child.tag.split("}", 1)[1]] = (child.text or "").strip()
        if ev:
            history.append(ev)
    return props, history


def _exiftool(path: Path) -> dict[str, Any] | None:
    if not shutil.which("exiftool"):
        return None
    try:
        # absolute path: a file named "-w ..." or "-@" must never reach exiftool as an option
        out = subprocess.run(["exiftool", "-json", "-G", "-n", str(Path(path).resolve())],
                             capture_output=True, text=True, timeout=60)
        return json.loads(out.stdout)[0]
    except (subprocess.SubprocessError, json.JSONDecodeError, IndexError):
        return None


def extract(path: Path) -> Metadata:
    md = Metadata()
    with Image.open(path) as img:
        md.width, md.height = img.size
        exif = img.getexif()
        for tag, value in exif.items():
            md.exif[ExifTags.TAGS.get(tag, f"0x{tag:04x}")] = value
        try:
            for tag, value in exif.get_ifd(0x8769).items():
                name = ExifTags.TAGS.get(tag, f"0x{tag:04x}")
                if name == "MakerNote":
                    md.has_makernote = True
                    continue
                md.exif[name] = value
        except Exception:  # noqa: BLE001
            pass
        try:
            for tag, value in exif.get_ifd(0x8825).items():
                md.gps[ExifTags.GPSTAGS.get(tag, f"0x{tag:04x}")] = value
        except Exception:  # noqa: BLE001
            pass
        raw_exif = img.info.get("exif")
        if raw_exif:
            md.thumbnail = _ifd1_thumbnail(raw_exif)
            md.has_makernote = md.has_makernote or b"Nikon" in raw_exif[:4096] or 0x927C in exif.get_ifd(0x8769)
        xmp_raw = img.info.get("xmp") or img.info.get("XML:com.adobe.xmp")
        if xmp_raw:
            md.xmp, md.xmp_history = _parse_xmp(xmp_raw)
        try:
            iptc = IptcImagePlugin.getiptcinfo(img) or {}
            names = {(2, 5): "ObjectName", (2, 80): "By-line", (2, 55): "DateCreated", (2, 110): "Credit",
                     (2, 115): "Source", (2, 116): "CopyrightNotice", (2, 120): "Caption", (2, 25): "Keywords"}
            for k, v in iptc.items():
                md.iptc[names.get(k, f"{k[0]}:{k[1]}")] = v
        except Exception:  # noqa: BLE001
            pass
        if img.format in ("PNG", "WEBP", "GIF"):
            for k, v in img.info.items():
                if isinstance(v, str) and k not in ("xmp", "XML:com.adobe.xmp"):
                    md.png_text[k] = v
    md.exiftool = _exiftool(path)
    return md


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

def _parse_exif_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().strip("\x00")
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            continue
    return None


def _offset(text: Any) -> timedelta | None:
    m = re.match(r"([+-])(\d{2}):(\d{2})", str(text or ""))
    if not m:
        return None
    sign = 1 if m.group(1) == "+" else -1
    return sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))


def _gps_datetime(gps: dict[str, Any]) -> datetime | None:
    date, t = gps.get("GPSDateStamp"), gps.get("GPSTimeStamp")
    if not date or not t:
        return None
    try:
        d = datetime.strptime(str(date).strip("\x00"), "%Y:%m:%d")
        h, m, s = (float(x) for x in t)
        return d + timedelta(hours=h, minutes=m, seconds=s)
    except (ValueError, TypeError):
        return None


def _match_any(text: str, names: list[str]) -> str | None:
    low = text.lower()
    return next((n for n in names if n in low), None)


def rules(md: Metadata, jpeg_kinds: list[str] | None = None, now: datetime | None = None) -> list[Finding]:
    out: list[Finding] = []
    now = now or datetime.now()
    make = str(md.exif.get("Make", "")).strip("\x00 ").strip()
    model = str(md.exif.get("Model", "")).strip("\x00 ").strip()
    software = " ".join(str(x) for x in (md.exif.get("Software", ""), md.xmp.get("xmp:CreatorTool", ""),
                                          md.xmp.get("tiff:Software", "")) if x)

    if md.empty:
        out.append(Finding("M00-stripped", "No metadata", "info", 0.0,
                           "The file carries no EXIF, XMP, IPTC or text metadata. Social platforms and messaging apps strip "
                           "it on upload, so this says nothing about authenticity - but it removes every metadata check below."))
        return out

    editor = _match_any(software, EDITORS)
    if editor:
        out.append(Finding("M01-editor", "Saved by editing software", "edited", 0.6,
                           f"The software field names '{software.strip()}'. The file was last written by an image editor; "
                           "that shows processing, not what was changed."))
    gen = _match_any(software, GENERATORS)
    if gen:
        out.append(Finding("M02-generator-software", "Written by a generative-AI tool", "generated", 0.8,
                           f"The software field names '{software.strip()}' (a generative tool)."))

    dto = _parse_exif_time(md.exif.get("DateTimeOriginal"))
    mod = _parse_exif_time(md.exif.get("DateTime"))
    if dto and mod and abs((mod - dto).total_seconds()) > 60:
        out.append(Finding("M03-modified-after-capture", "Modified after capture", "edited", 0.4,
                           f"DateTimeOriginal is {dto} but the file's DateTime (last modified) is {mod}."))
    elif dto and mod:
        out.append(Finding("M03-modified-after-capture", "Capture and modify times agree", "consistent", 0.2,
                           "DateTimeOriginal and DateTime are within a minute of each other."))

    gps_dt = _gps_datetime(md.gps)
    if dto and gps_dt:
        off = _offset(md.exif.get("OffsetTimeOriginal"))
        if off is not None:
            diff = abs((dto - off) - gps_dt)
            if diff > timedelta(minutes=10):
                out.append(Finding("M04-gps-time", "Capture time contradicts GPS time", "inconsistent", 0.6,
                                   f"Local capture time {dto} {md.exif.get('OffsetTimeOriginal')} is {diff} away from the GPS UTC time {gps_dt}."))
            else:
                out.append(Finding("M04-gps-time", "Capture time matches GPS time", "consistent", 0.3,
                                   "Capture time and GPS UTC time agree within ten minutes."))
        else:
            delta = (dto - gps_dt).total_seconds() / 60
            nearest = round(delta / 15) * 15
            if abs(delta) > 14 * 60 + 10 or abs(delta - nearest) > 10:
                out.append(Finding("M04-gps-time", "Capture time does not fit any time zone of the GPS time", "inconsistent", 0.5,
                                   f"Capture {dto} vs GPS UTC {gps_dt}: a difference of {delta:.0f} minutes is not a whole time-zone offset."))

    if dto and (dto > now + timedelta(days=1) or dto.year < 1990):
        out.append(Finding("M05-impossible-date", "Implausible capture date", "inconsistent", 0.5,
                           f"DateTimeOriginal {dto} is in the future or before digital photography was common."))

    ew, eh = md.exif.get("ExifImageWidth"), md.exif.get("ExifImageHeight")
    if ew and eh and md.width and md.height:
        if {int(ew), int(eh)} != {md.width, md.height}:
            out.append(Finding("M06-dimensions", "Recorded dimensions differ from the pixels", "edited", 0.5,
                               f"EXIF says {ew}x{eh}; the image is {md.width}x{md.height}: resized or cropped after capture."))
        else:
            out.append(Finding("M06-dimensions", "Recorded dimensions match", "consistent", 0.2,
                               f"EXIF dimensions {ew}x{eh} match the image."))

    if md.thumbnail:
        try:
            with Image.open(io.BytesIO(md.thumbnail)) as th_full:
                th = _strip_letterbox(th_full)
                tw, thh = th.size
                ratio_main = md.width / md.height if md.height else 0
                ratio_th = tw / thh if thh else 0
                swapped = 1 / ratio_th if ratio_th else 0
                if ratio_main and min(abs(ratio_main - ratio_th), abs(ratio_main - swapped)) / ratio_main > 0.03:
                    out.append(Finding("M07-thumbnail-aspect", "EXIF thumbnail has a different shape", "edited", 0.6,
                                       f"The embedded thumbnail is {tw}x{thh} (ratio {ratio_th:.2f}) but the image is "
                                       f"{md.width}x{md.height} (ratio {ratio_main:.2f}): cropped after the thumbnail was made."))
                else:
                    diff = _thumbnail_difference(th, md)
                    if diff is not None and diff > 18:
                        out.append(Finding("M08-thumbnail-content", "EXIF thumbnail shows different content", "edited", 0.7,
                                           f"The embedded thumbnail differs from the image (mean difference {diff:.1f}/255): "
                                           "the picture was changed without updating the thumbnail."))
                    elif diff is not None:
                        out.append(Finding("M08-thumbnail-content", "EXIF thumbnail matches the image", "consistent", 0.3,
                                           f"Mean difference {diff:.1f}/255 between thumbnail and downscaled image."))
        except Exception:  # noqa: BLE001
            pass

    if make and not any(k in md.exif for k in ("ExposureTime", "FNumber", "ISOSpeedRatings", "PhotographicSensitivity")):
        out.append(Finding("M09-camera-without-exposure", "Camera named, but no exposure data", "inconsistent", 0.3,
                           f"Make '{make}' is set but exposure time, aperture and ISO are absent; cameras always record them. "
                           "The metadata may have been rewritten or copied."))
    if make and _match_any(make, CAMERA_MAKERNOTE_BRANDS) and not md.has_makernote and "ExposureTime" in md.exif:
        out.append(Finding("M10-makernote-missing", "Manufacturer MakerNote missing", "edited", 0.35,
                           f"{make} cameras write a proprietary MakerNote; it is gone, which happens when software "
                           "re-writes the metadata."))

    saved = [h for h in md.xmp_history if h.get("action") in ("saved", "converted", "derived", "edited", "produced")]
    if saved:
        agents = sorted({h.get("softwareAgent", "?") for h in saved})
        out.append(Finding("M11-xmp-history", "Editing history recorded in XMP", "edited", 0.6,
                           f"{len(saved)} xmpMM:History events ({', '.join(sorted({h.get('action') for h in saved}))}) "
                           f"by {', '.join(agents)}."))
    if any(k.startswith("crs:") for k in md.xmp):
        out.append(Finding("M12-raw-development", "Developed in Adobe Camera Raw / Lightroom", "edited", 0.3,
                           "Camera Raw settings are present: exposure/colour adjustments were applied (normal for RAW workflows)."))

    dst = str(md.xmp.get("Iptc4xmpExt:DigitalSourceType", "")) + " " + " ".join(str(v) for v in md.iptc.values())
    for key, desc in AI_DST.items():
        if key in dst.lower().replace(" ", ""):
            out.append(Finding("M13-declared-ai", "AI generation declared in metadata", "generated", 0.9,
                               f"IPTC DigitalSourceType = {key}: {desc}. This is a self-declaration by the creating software."))
            break

    params = md.png_text.get("parameters", "")
    if params and re.search(r"Steps:\s*\d+.*Sampler:", params, re.S):
        out.append(Finding("M14-sd-parameters", "Stable Diffusion generation parameters embedded", "generated", 0.9,
                           "A PNG 'parameters' text chunk holds a prompt with Steps/Sampler/CFG settings (AUTOMATIC1111 format)."))
    if "prompt" in md.png_text or "workflow" in md.png_text:
        out.append(Finding("M14-sd-parameters", "ComfyUI workflow embedded", "generated", 0.9,
                           "PNG text chunks 'prompt'/'workflow' hold a ComfyUI generation graph."))
    for key in ("Software", "Comment", "Description", "Source"):
        val = md.png_text.get(key, "")
        g = _match_any(val, GENERATORS)
        if g:
            out.append(Finding("M15-png-generator", f"PNG {key} names a generator", "generated", 0.7, f"{key} = '{val[:120]}'"))

    kinds = jpeg_kinds or []
    if make and "JFIF" in kinds and "Exif" in kinds:
        out.append(Finding("M16-jfif-plus-camera", "JFIF header next to camera EXIF", "edited", 0.25,
                           "Camera firmware writes EXIF without a JFIF header; JFIF is added by libjpeg-based software, "
                           "so this file was probably re-encoded after capture."))
    if "Photoshop IRB" in kinds or "Adobe" in kinds:
        out.append(Finding("M17-adobe-segments", "Adobe/Photoshop segments present", "edited", 0.4,
                           "APP13 Photoshop resources or an APP14 Adobe segment: the file was saved by Adobe software."))
    if make or model:
        out.append(Finding("M18-camera", "Camera identification", "info", 0.0, f"Make '{make}', model '{model}'."))
    return out


def _strip_letterbox(thumb: Image.Image) -> Image.Image:
    """Cameras (e.g. Nikon) write 4:3 thumbnails with a 3:2 picture letterboxed inside black bars."""
    import numpy as np

    a = np.asarray(thumb.convert("L"), dtype=float)
    rows = np.where(a.mean(axis=1) > 12)[0]
    cols = np.where(a.mean(axis=0) > 12)[0]
    if len(rows) < 8 or len(cols) < 8:
        return thumb.copy()
    top, bottom, left, right = rows[0], rows[-1] + 1, cols[0], cols[-1] + 1
    if (top, bottom, left, right) == (0, a.shape[0], 0, a.shape[1]):
        return thumb.copy()
    return thumb.crop((int(left), int(top), int(right), int(bottom)))


def _thumbnail_difference(thumb: Image.Image, md: Metadata) -> float | None:
    """Mean absolute difference between the thumbnail and the main image (needs the main image path)."""
    main = getattr(md, "_main_image", None)
    if main is None:
        return None
    import numpy as np

    t = thumb.convert("L")
    m = main.convert("L").resize(t.size, Image.BILINEAR)
    a, b = np.asarray(t, dtype=float), np.asarray(m, dtype=float)
    # thumbnails may carry letterbox bars; compare the central 80%
    h, w = a.shape
    sl = (slice(h // 10, h - h // 10), slice(w // 10, w - w // 10))
    return float(np.abs(a[sl] - b[sl]).mean())


def analyse(path: Path, jpeg_kinds: list[str] | None = None) -> tuple[Metadata, list[Finding]]:
    md = extract(path)
    with Image.open(path) as img:
        # only compared at thumbnail size, so decode a preview, never the full canvas; formats
        # without draft decoding (PNG, WebP) are skipped above the analysis decode limit
        if img.width * img.height <= MAX_PREVIEW_PIXELS:
            img.draft("RGB", (1024, 1024))
            img.thumbnail((1024, 1024))
            md._main_image = img.copy()  # type: ignore[attr-defined]
    findings = rules(md, jpeg_kinds)
    md.__dict__.pop("_main_image", None)
    return md, findings
