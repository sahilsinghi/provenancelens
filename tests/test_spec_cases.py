"""The five acceptance cases from the project brief."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from provlens import c2pa_check, qtables, report
from provlens.analyze import analyse
from provlens.jpeg import parse

from .conftest import jpg, reopen


def _overlaps(a, b) -> bool:
    return not (a[2] <= b[0] or a[0] >= b[2] or a[3] <= b[1] or a[1] >= b[3])


# 1. A validly signed image shows its signer and edit history ---------------------------------

def test_valid_credentials_show_signer_and_history(tmp_path, photos, identity):
    from provlens import testsign

    original = tmp_path / "original.jpg"
    original.write_bytes(jpg(photos["astronaut"], 90))
    signed = testsign.sign(original, tmp_path / "signed.jpg", identity, title="original.jpg")
    edited_src = tmp_path / "edited-src.jpg"
    edited_src.write_bytes(jpg(reopen(signed.read_bytes()).crop((20, 20, 236, 236)), 90))
    edited = testsign.sign(edited_src, tmp_path / "edited.jpg", identity,
                           actions=[{"action": "c2pa.cropped"}, {"action": "c2pa.color_adjustments"}], parent=signed)

    r = analyse(edited, [identity.root_pem])
    c = r["c2pa"]
    assert c["state"] == "Trusted"
    assert any("ProvenanceLens Test Root" in t for t in c["trust_anchors"])
    assert c["active"]["signer"]["common_name"] == "ProvenanceLens Test Signer"
    assert [a["action"] for a in c["active"]["actions"]] == ["c2pa.opened", "c2pa.cropped", "c2pa.color_adjustments"]
    assert c["hard_binding"]["checked"] and c["hard_binding"]["match"]
    # history: the active manifest points at the earlier signed version
    assert len(c["manifests"]) == 2
    ing = c["active"]["ingredients"][0]
    assert ing["relationship"] == "parentOf" and ing["manifest"] in {m["label"] for m in c["manifests"]}
    assert any(s["supports"] == "declared" and "cropped" in s["detail"] for s in r["verdict"]["signals"])
    assert any(s["supports"] == "authentic" for s in r["verdict"]["signals"])

    page = report.render_html(r)
    assert "ProvenanceLens Test Signer" in page and "Ingredient graph" in page and "c2pa.cropped" in page

    # the same file without the trust anchor: valid, but the identity is unverified
    untrusted = c2pa_check.check(edited, None)
    assert untrusted.state == "Valid"
    assert "signingCredential.untrusted" in {s["code"] for s in untrusted.statuses}
    assert "not on your trust list" in untrusted.summary


# 2. One flipped byte in the scan data breaks the hard binding --------------------------------

def test_flipped_byte_breaks_hard_binding(tmp_path, photos, identity):
    from provlens import testsign

    src = tmp_path / "photo.jpg"
    src.write_bytes(jpg(photos["coffee"], 90))
    signed = testsign.sign(src, tmp_path / "signed.jpg", identity)
    data = bytearray(signed.read_bytes())
    info = parse(bytes(data))
    sos = max(s.offset for s in info.segments if s.marker == 0xDA)
    pos = sos + (len(data) - sos) // 2
    data[pos] ^= 0x01
    tampered = tmp_path / "tampered.jpg"
    tampered.write_bytes(bytes(data))

    r = analyse(tampered, [identity.root_pem], maps=False)
    c = r["c2pa"]
    assert c["state"] == "Invalid"
    failures = {s["code"]: s["explain"] for s in c["statuses"] if s["kind"] == "failure"}
    assert "assertion.dataHash.mismatch" in failures
    assert "changed after signing" in failures["assertion.dataHash.mismatch"]
    # ProvenanceLens recomputes the binding itself and agrees with the SDK
    assert c["hard_binding"]["checked"] and c["hard_binding"]["match"] is False
    assert "own recomputation" in c["summary"]
    assert r["verdict"]["editing_level"] == "strong"
    assert r["verdict"]["signals"][0]["supports"] == "edited"


# 3. Phone JPEG -> platform re-upload: the encoder fingerprint changes ------------------------

@pytest.mark.skipif(shutil.which("sips") is None, reason="needs macOS sips (Apple ImageIO encoder)")
def test_platform_reupload_changes_quantisation_fingerprint(tmp_path, photos):
    png = tmp_path / "capture.png"
    photos["rocket"].save(png)
    phone = tmp_path / "phone.jpg"
    subprocess.run(["sips", "-s", "format", "jpeg", "-s", "formatOptions", "85", str(png), "--out", str(phone)],
                   check=True, capture_output=True)
    info = parse(phone.read_bytes())
    before = qtables.describe(info.luma, info.chroma)
    assert before["best"]["family"] == "apple"
    assert before["best"]["exact"]

    im = reopen(phone.read_bytes())
    platform = tmp_path / "platform.jpg"
    platform.write_bytes(jpg(im.resize((int(im.width * 0.8), int(im.height * 0.8))), 75))
    info = parse(platform.read_bytes())
    after = qtables.describe(info.luma, info.chroma)
    assert after["best"]["family"] == "ijg" and after["best"]["quality"] == "q75" and after["best"]["exact"]

    r = analyse(platform, maps=False)
    match = next(s for s in r["verdict"]["signals"] if s["id"] == "qtable.match")
    assert "IJG" in match["title"]
    # a re-upload is not manipulation: nothing should push the verdict past weak
    assert r["verdict"]["editing_level"] in ("none", "weak")


# 4. A splice is localised and the double-compression flag is raised --------------------------

@pytest.mark.parametrize("x,y,q_bg,q_donor,q_final", [
    (40, 40, 70, 45, 90), (120, 60, 70, 45, 90), (60, 140, 75, 50, 92), (150, 150, 75, 50, 92),
])
def test_splice_is_localised(tmp_path, photos, x, y, q_bg, q_donor, q_final):
    bg = reopen(jpg(photos["astronaut"], q_bg))  # a downloaded JPEG
    donor = reopen(jpg(photos["chelsea"].crop((60, 20, 160, 120)), q_donor))  # a patch from another JPEG
    bg.paste(donor, (x, y))
    path = tmp_path / "splice.jpg"
    path.write_bytes(jpg(bg, q_final))
    box = [x, y, x + 100, y + 100]

    r = analyse(path)
    hits = {name for name in ("ghost", "ela")
            if any(_overlaps(reg["bbox"], box) for reg in r["pixel"][name]["regions"])}
    assert hits, f"neither ghost nor ELA found a region over {box}"
    assert r["jpeg"]["djpeg"]["double"] is True
    assert r["verdict"]["editing_level"] in ("moderate", "strong")
    assert any(s["module"] == "pixel" and s["supports"] == "edited" for s in r["verdict"]["signals"])


# 5. A stripped PNG: no provenance, limited forensic signal -----------------------------------

def test_stripped_png_reports_limited_signal(tmp_path, photos):
    path = tmp_path / "stripped.png"
    photos["coffee"].save(path, "PNG")
    r = analyse(path)
    v = r["verdict"]
    assert v["limited_signal"] is True
    assert v["headline"].startswith("No provenance, limited forensic signal")
    assert v["editing_level"] == "none" and v["generation_score"] == 0
    assert r["c2pa"]["present"] is False
    assert r["metadata"]["empty"] is True
    assert "jpeg" not in r  # no tables, so no fingerprint and no double-compression test
    assert "not applicable" in report.render_html(r)
