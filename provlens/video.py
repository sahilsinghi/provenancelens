"""Video (MP4 / QuickTime): content credentials, container metadata, sampled frames.

Pixel forensics are not run on video frames: H.264/HEVC frames carry no JPEG
quantisation tables and the image thresholds were never calibrated on them.
What a video report does contain:

* C2PA validation (c2pa-rs checks the BMFF hash that binds the manifest to the
  media boxes, the signature and the certificate chain),
* container rules over ffprobe's tags (V01-V06 below),
* a contact sheet of evenly spaced frames for the analyst.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from PIL import Image

from provlens.metadata import EDITORS, GENERATORS, Finding

VIDEO_TYPES = {"video/mp4", "video/quicktime"}
VIDEO_EDITORS = EDITORS + ["premiere", "final cut", "imovie", "davinci", "resolve", "capcut", "inshot", "vn video",
                           "kinemaster", "after effects", "handbrake", "shotcut", "kdenlive"]


def _input(path: Path) -> str:
    """Absolute ``file:`` URL so a name like ``concat:a|b`` or ``-i`` is never read as a protocol or option."""
    return "file:" + str(Path(path).resolve())


# Only local files may be opened, even if a container references other media (dref, playlists).
_SAFE = ["-protocol_whitelist", "file"]


def available() -> bool:
    return bool(shutil.which("ffprobe") and shutil.which("ffmpeg"))


def probe(path: Path) -> dict[str, Any]:
    if not shutil.which("ffprobe"):
        return {}
    p = subprocess.run(["ffprobe", "-v", "error", *_SAFE, "-show_format", "-show_streams", "-of", "json", _input(path)],
                       capture_output=True, text=True, timeout=60)
    return json.loads(p.stdout or "{}")


def summary(info: dict[str, Any]) -> dict[str, Any]:
    fmt = info.get("format", {}) or {}
    video = next((s for s in info.get("streams", []) if s.get("codec_type") == "video"), {})
    audio = next((s for s in info.get("streams", []) if s.get("codec_type") == "audio"), {})
    return {
        "container": fmt.get("format_long_name") or fmt.get("format_name"),
        "duration_s": round(float(fmt.get("duration", 0) or 0), 2),
        "video": f"{video.get('codec_name', '?')} {video.get('width', '?')}x{video.get('height', '?')} "
                 f"@ {video.get('avg_frame_rate', '?')}" if video else None,
        "audio": f"{audio.get('codec_name')} {audio.get('sample_rate', '')} Hz" if audio else None,
        "tags": {k: v for k, v in (fmt.get("tags") or {}).items()},
        "video_handler": (video.get("tags") or {}).get("handler_name"),
        "width": video.get("width"), "height": video.get("height"),
    }


def _time(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def rules(info: dict[str, Any]) -> list[Finding]:
    s = summary(info)
    tags = {k.lower(): str(v) for k, v in s["tags"].items()}
    out: list[Finding] = []
    encoder = tags.get("encoder", "")
    software = " ".join(tags.get(k, "") for k in ("com.apple.quicktime.software", "software", "encoder", "comment", "title"))
    make = tags.get("com.apple.quicktime.make") or tags.get("make") or ""
    model = tags.get("com.apple.quicktime.model") or tags.get("model") or ""
    android = tags.get("com.android.version")

    gen = next((g for g in GENERATORS + ["sora", "veo", "runway", "pika", "kling", "luma dream machine"]
                if g in software.lower()), None)
    if gen:
        out.append(Finding("V05-generator", "Container names a generative-AI tool", "generated", 0.8,
                           f"The container's software/comment tags name '{gen}'."))
    editor = next((e for e in VIDEO_EDITORS if e in software.lower()), None)
    if editor:
        out.append(Finding("V02-editor", "Exported by editing software", "edited", 0.6,
                           f"The container's software tags name '{editor}'."))
    if encoder.lower().startswith("lavf") or (s.get("video_handler") or "").lower() in ("videohandler",):
        out.append(Finding("V01-ffmpeg-mux", "Written by FFmpeg (libavformat)", "edited", 0.4,
                           f"encoder tag '{encoder or 'n/a'}', handler '{s.get('video_handler')}'. Phones and cameras do "
                           "not write this; FFmpeg-based editors, converters and many platforms do. A re-encode or "
                           "re-mux, not necessarily a content edit."))
    if make or android:
        out.append(Finding("V03-capture-device", "Capture device tags present", "consistent", 0.2,
                           f"make '{make}', model '{model}'" + (f", Android {android}" if android else "")
                           + ". Easy to forge, but platforms and editors usually drop them."))
    created = _time(tags.get("creation_time"))
    apple_created = _time(tags.get("com.apple.quicktime.creationdate"))
    if created and apple_created:
        delta = abs((created - apple_created).total_seconds())
        if delta > 120:
            out.append(Finding("V04-creation-times", "Creation times disagree", "inconsistent", 0.5,
                               f"creation_time {created.isoformat()} vs Apple creationdate {apple_created.isoformat()} "
                               f"({delta / 60:.0f} min apart): written at different times, e.g. by a later export."))
        else:
            out.append(Finding("V04-creation-times", "Creation times agree", "consistent", 0.2,
                               "creation_time and the Apple creationdate tag agree."))
    if not s["tags"] or set(k.lower() for k in s["tags"]) <= {"major_brand", "minor_version", "compatible_brands"}:
        out.append(Finding("V06-no-tags", "No descriptive container tags", "info", 0.0,
                           "Only the file-type brands are present. Platforms strip tags on upload, so this says "
                           "nothing about authenticity."))
    return out


def frames(path: Path, n: int = 6, duration: float | None = None) -> list[Image.Image]:
    if not shutil.which("ffmpeg"):
        return []
    duration = duration or 0.0
    times = [duration * (i + 0.5) / n for i in range(n)] if duration > 0 else [0.0]
    out = []
    for t in times:
        p = subprocess.run(["ffmpeg", "-v", "error", *_SAFE, "-ss", f"{t:.3f}", "-i", _input(path), "-frames:v", "1",
                            "-f", "image2pipe", "-vcodec", "png", "-"], capture_output=True, timeout=60)
        if p.returncode == 0 and p.stdout:
            out.append(Image.open(io.BytesIO(p.stdout)).convert("RGB"))
    return out


def contact_sheet(imgs: list[Image.Image], cols: int = 3, cell_w: int = 320) -> bytes:
    if not imgs:
        return b""
    cell_h = int(cell_w * imgs[0].height / imgs[0].width)
    rows = (len(imgs) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * cell_w + (cols - 1) * 4, rows * cell_h + (rows - 1) * 4), (24, 24, 24))
    for i, im in enumerate(imgs):
        sheet.paste(im.resize((cell_w, cell_h)), ((i % cols) * (cell_w + 4), (i // cols) * (cell_h + 4)))
    buf = io.BytesIO()
    sheet.save(buf, "JPEG", quality=85)
    return buf.getvalue()
