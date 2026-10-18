from __future__ import annotations

from PIL import Image, PngImagePlugin

from provlens import metadata
from provlens.analyze import analyse

from .conftest import jpg


def _exif(**tags):
    ex = Image.Exif()
    names = {"Make": 0x010F, "Model": 0x0110, "Software": 0x0131, "DateTime": 0x0132}
    sub = {"DateTimeOriginal": 0x9003, "ExifImageWidth": 0xA002, "ExifImageHeight": 0xA003,
           "ExposureTime": 0x829A, "FNumber": 0x829D}
    for k, v in tags.items():
        if k in names:
            ex[names[k]] = v
        else:
            ex.get_ifd(0x8769)[sub[k]] = v
    return ex.tobytes()


def _rules(tmp_path, im, **tags):
    p = tmp_path / "m.jpg"
    p.write_bytes(jpg(im, 90, exif=_exif(**tags)))
    _, findings = metadata.analyse(p, None)
    return {f.rule: f for f in findings}


def test_editor_and_modified_after_capture(tmp_path, photos):
    f = _rules(tmp_path, photos["coffee"], Make="Canon", Model="Canon EOS R5", Software="Adobe Photoshop 25.0 (Macintosh)",
               DateTime="2025:06:02 18:00:00", DateTimeOriginal="2025:06:01 09:30:00",
               ExposureTime=(1, 200), FNumber=(28, 10))
    assert f["M01-editor"].status == "edited"
    assert f["M03-modified-after-capture"].status == "edited"
    assert f["M10-makernote-missing"].status == "edited"  # a Canon file always carries a MakerNote


def test_dimensions_contradict_pixels(tmp_path, photos):
    f = _rules(tmp_path, photos["coffee"], ExifImageWidth=4000, ExifImageHeight=3000)
    assert f["M06-dimensions"].status == "edited"


def test_consistent_times(tmp_path, photos):
    f = _rules(tmp_path, photos["coffee"], DateTime="2025:06:01 09:30:00", DateTimeOriginal="2025:06:01 09:30:00")
    assert f["M03-modified-after-capture"].status == "consistent"


def test_impossible_date(tmp_path, photos):
    f = _rules(tmp_path, photos["coffee"], DateTimeOriginal="2091:01:01 00:00:00")
    assert f["M05-impossible-date"].status == "inconsistent"


def test_camera_without_exposure(tmp_path, photos):
    f = _rules(tmp_path, photos["coffee"], Make="NIKON CORPORATION", Model="NIKON Z 8")
    assert f["M09-camera-without-exposure"].status == "inconsistent"


def test_stable_diffusion_parameters_in_png(tmp_path, photos):
    info = PngImagePlugin.PngInfo()
    info.add_text("parameters", "a lighthouse at dusk\nSteps: 30, Sampler: DPM++ 2M, CFG scale: 7, Seed: 1")
    p = tmp_path / "sd.png"
    photos["coffee"].save(p, pnginfo=info)
    r = analyse(p, maps=False)
    rules = {f["rule"] for f in r["metadata"]["findings"]}
    assert "M14-sd-parameters" in rules
    assert r["verdict"]["generation_score"] >= 0.5
    assert "AI generation is declared" in r["verdict"]["headline"]


def test_iptc_digital_source_type_in_xmp(tmp_path, photos):
    from provlens.evaluate import XMP_AI

    p = tmp_path / "ai.jpg"
    p.write_bytes(jpg(photos["coffee"], 90, xmp=XMP_AI))
    r = analyse(p, maps=False)
    assert "M13-declared-ai" in {f["rule"] for f in r["metadata"]["findings"]}
    assert r["verdict"]["generation_score"] >= 0.5


def test_no_metadata_is_neutral(tmp_path, photos):
    p = tmp_path / "bare.jpg"
    p.write_bytes(jpg(photos["coffee"], 90))
    md, findings = metadata.analyse(p, None)
    assert md.empty
    assert [f.rule for f in findings] == ["M00-stripped"] and findings[0].status == "info"
