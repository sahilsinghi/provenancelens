"""Stretch goal: MP4 / QuickTime support (C2PA over BMFF, container rules, sampled frames)."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from provlens import c2pa_check, report, testsign
from provlens.analyze import analyse

pytestmark = pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="needs ffmpeg/ffprobe")


@pytest.fixture(scope="module")
def clip(tmp_path_factory):
    out = tmp_path_factory.mktemp("video") / "clip.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc2=size=320x240:rate=25",
                    "-t", "2", "-pix_fmt", "yuv420p", "-c:v", "libx264", str(out)], check=True)
    return out


def test_ffmpeg_written_clip(clip):
    r = analyse(clip)
    assert r["format"] == "video/mp4"
    assert r["c2pa"]["state"] == "absent"
    assert "V01-ffmpeg-mux" in {f["rule"] for f in r["metadata"]["findings"]}
    assert r["video"]["frames_sampled"] == 6
    assert r["image"]["contact_sheet"] is True
    assert "pixel" not in r and "jpeg" not in r
    page = report.render_html(r)
    assert "frames sampled" in page and "never calibrated on video" in page


def test_signed_clip_validates_and_one_bit_breaks_bmff_hash(clip, identity, tmp_path):
    signed = testsign.sign(clip, tmp_path / "signed.mp4", identity)
    assert c2pa_check.check(signed, [identity.root_pem]).state == "Trusted"
    data = bytearray(signed.read_bytes())
    data[data.find(b"mdat") + 4000] ^= 0x01
    tampered = tmp_path / "tampered.mp4"
    tampered.write_bytes(bytes(data))
    r = analyse(tampered, [identity.root_pem])
    assert r["c2pa"]["state"] == "Invalid"
    assert "assertion.bmffHash.mismatch" in {s["code"] for s in r["c2pa"]["statuses"] if s["kind"] == "failure"}
    assert r["verdict"]["editing_level"] == "strong"


def test_editor_and_creation_time_rules(clip, tmp_path):
    out = tmp_path / "exported.mov"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(clip), "-c", "copy",
                    "-metadata", "com.apple.quicktime.software=Final Cut Pro 11.0",
                    "-metadata", "com.apple.quicktime.creationdate=2025-06-01T09:30:00+0000",
                    "-metadata", "creation_time=2025-06-03T18:00:00Z", "-movflags", "use_metadata_tags", str(out)], check=True)
    r = analyse(out)
    assert r["format"] == "video/quicktime"
    rules = {f["rule"]: f["status"] for f in r["metadata"]["findings"]}
    assert rules.get("V02-editor") == "edited"
    assert rules.get("V04-creation-times") == "inconsistent"
