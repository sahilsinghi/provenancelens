"""CLI, web server, HTML report and the signed report card."""

from __future__ import annotations

import json

import pytest

from provlens import c2pa_check, card
from provlens.analyze import analyse
from provlens.cli import main

from .conftest import jpg, reopen


@pytest.fixture
def double_saved(tmp_path, photos):
    p = tmp_path / "double.jpg"
    p.write_bytes(jpg(reopen(jpg(photos["rocket"], 60)), 92))
    return p


def test_cli_analyze_writes_reports_and_sets_exit_code(tmp_path, photos, double_saved, capsys):
    single = tmp_path / "single.jpg"
    single.write_bytes(jpg(photos["rocket"], 90))
    assert main(["analyze", str(single), "--json", str(tmp_path / "s.json"), "-q"]) == 0
    assert main(["analyze", str(double_saved), "--html", str(tmp_path / "d.html"), "--json", str(tmp_path / "d.json")]) == 1
    out = capsys.readouterr().out
    assert "Saved as JPEG more than once" in out
    doc = json.loads((tmp_path / "d.json").read_text())
    assert doc["verdict"]["editing_level"] == "moderate"
    assert "heatmap_png_b64" not in json.dumps(doc)  # images are left out unless asked for
    assert "<html" in (tmp_path / "d.html").read_text()


def test_cli_rejects_non_images(tmp_path, capsys):
    p = tmp_path / "notes.jpg"
    p.write_text("not an image")
    assert main(["analyze", str(p)]) == 2
    assert "not a supported image format" in capsys.readouterr().out


def test_cli_triage_ranks_by_evidence(tmp_path, photos, double_saved):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "a-single.jpg").write_bytes(jpg(photos["coffee"], 90))
    (inbox / "b-double.jpg").write_bytes(double_saved.read_bytes())
    photos["chelsea"].save(inbox / "c.png")
    assert main(["triage", str(inbox), "--out", str(tmp_path / "out")]) == 0
    rows = json.loads((tmp_path / "out" / "triage.json").read_text())
    assert rows[0]["name"] == "b-double.jpg"
    assert (tmp_path / "out" / "index.html").exists()
    assert all((tmp_path / "out" / r["report"]).exists() for r in rows)


def test_cli_testsign_roundtrip(tmp_path, photos):
    src = tmp_path / "in.jpg"
    src.write_bytes(jpg(photos["coffee"], 90))
    assert main(["testsign", "init", str(tmp_path / "id")]) == 0
    assert main(["testsign", "sign", str(src), str(tmp_path / "out.jpg"), "--id", str(tmp_path / "id"),
                 "--action", "c2pa.color_adjustments"]) == 0
    r = c2pa_check.check(tmp_path / "out.jpg", [tmp_path / "id" / "test-root.pem"])
    assert r.state == "Trusted"
    assert [a["action"] for a in r.active["actions"]] == ["c2pa.created", "c2pa.color_adjustments"]


def test_signed_report_card_binds_the_analysis(tmp_path, double_saved, identity):
    r = analyse(double_saved)
    out = card.write(r, tmp_path / "card.png", analysed=double_saved, identity_dir=identity.root_pem.parent)
    c = c2pa_check.check(out, [identity.root_pem])
    assert c.state == "Trusted"
    assert "org.provenancelens.analysis" in c.active["assertions"]
    assert c.active["ingredients"][0]["relationship"] == "componentOf"
    import c2pa

    with c2pa.Reader(str(out)) as reader:
        store = json.loads(reader.json())
    active = store["manifests"][store["active_manifest"]]
    data = next(a["data"] for a in active["assertions"] if a["label"] == "org.provenancelens.analysis")
    assert data["analysed"]["sha256"] == r["file"]["sha256"]
    assert data["editing_level"] == r["verdict"]["editing_level"]
    # the card is software-rendered, not AI output: ProvenanceLens must not call it generated
    again = analyse(out, [identity.root_pem], maps=False)
    assert again["verdict"]["generation_score"] < 0.5


def test_server_upload(photos, double_saved):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from provlens.server import create_app

    client = TestClient(create_app(max_bytes=5 * 1024 * 1024), base_url="http://localhost")
    assert client.get("/healthz").json()["ok"] is True
    assert "Choose or drop an image" in client.get("/").text
    with open(double_saved, "rb") as fh:
        res = client.post("/api/analyze", files={"file": ("upload.jpg", fh, "image/jpeg")})
    assert res.status_code == 200
    assert res.json()["file"]["name"] == "upload.jpg"
    assert res.json()["verdict"]["editing_level"] == "moderate"
    with open(double_saved, "rb") as fh:
        page = client.post("/analyze", files={"file": ("upload.jpg", fh, "image/jpeg")})
    assert page.status_code == 200 and "ProvenanceLens report" in page.text
    assert client.post("/api/analyze", files={"file": ("x.jpg", b"hello", "image/jpeg")}).status_code == 415
    small = TestClient(create_app(max_bytes=1000), base_url="http://localhost")
    with open(double_saved, "rb") as fh:
        assert small.post("/api/analyze", files={"file": ("big.jpg", fh, "image/jpeg")}).status_code == 413


def test_cli_trust_anchor_paths(tmp_path, photos, identity, capsys):
    """--trust arrives as strings; a signed image must still validate as Trusted, and a typo must fail loudly."""
    from provlens import testsign

    src = tmp_path / "in.jpg"
    src.write_bytes(jpg(photos["coffee"], 90))
    signed = testsign.sign(src, tmp_path / "signed.jpg", identity)
    assert main(["analyze", str(signed), "--trust", str(identity.root_pem), "--json", str(tmp_path / "r.json")]) == 0
    assert json.loads((tmp_path / "r.json").read_text())["c2pa"]["state"] == "Trusted"
    assert "(trusted)" in capsys.readouterr().out
    assert main(["analyze", str(signed), "--trust", str(tmp_path / "missing.pem")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_c2pa_check_failure_is_not_reported_as_absent(tmp_path, photos, monkeypatch):
    from provlens import c2pa_check as cc

    def boom(*a, **k):
        raise RuntimeError("reader crashed")

    monkeypatch.setattr(cc, "check", boom)
    p = tmp_path / "x.jpg"
    p.write_bytes(jpg(photos["coffee"], 90))
    r = analyse(p, maps=False)
    assert r["c2pa"]["state"] == "error"
    assert "unknown" in r["verdict"]["provenance"] and "No content credentials" not in r["verdict"]["provenance"]
    assert r["verdict"]["limited_signal"] is False
    assert any(s["id"] == "c2pa.error" for s in r["verdict"]["signals"])


def test_server_hardening(double_saved):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from provlens.server import create_app

    app = create_app(max_bytes=200_000)
    client = TestClient(app, base_url="http://127.0.0.1:8000")
    # DNS rebinding: a request that arrives with someone else's Host header is refused
    assert TestClient(app, base_url="http://attacker.example").get("/healthz").status_code == 400
    page = client.get("/")
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    with open(double_saved, "rb") as fh:
        report = client.post("/analyze", files={"file": ("<script>x</script>.jpg", fh, "image/jpeg")})
    assert report.status_code == 200
    assert "script-src" not in report.headers["content-security-policy"]  # reports may run no script at all
    assert "<script>x</script>" not in report.text
    # a body larger than the limit is refused from its declared length, before it is read
    big = client.post("/api/analyze", content=b"x" * 400_000,
                      headers={"content-type": "multipart/form-data; boundary=b"})
    assert big.status_code == 413
    # hostile file names cannot steer the temporary file
    with open(double_saved, "rb") as fh:
        odd = client.post("/api/analyze", files={"file": ("../../x\x00.j\npg", fh, "image/jpeg")})
    assert odd.status_code == 200


def test_cli_refuses_public_bind_without_allowed_host(capsys):
    assert main(["serve", "--host", "0.0.0.0"]) == 2
    assert "--allowed-host" in capsys.readouterr().err


def test_body_limit_cuts_off_an_undeclared_stream():
    """A chunked upload with no Content-Length is cut off once it passes the limit; the app never sees the rest."""
    import asyncio

    from provlens.server import BodyLimitMiddleware

    consumed = []

    async def app(scope, receive, send):  # stands in for the multipart parser: reads until the body ends
        while True:
            msg = await receive()
            consumed.append(len(msg.get("body", b"")))
            if not msg.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def endless():
        return {"type": "http.request", "body": b"x" * 10_000, "more_body": True}

    sent = []

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "method": "POST", "path": "/api/analyze", "headers": [(b"transfer-encoding", b"chunked")]}
    asyncio.run(BodyLimitMiddleware(app, limit=50_000)(scope, endless, send))
    assert sent[0]["status"] == 413
    assert sum(consumed) <= 50_000  # the oversized chunk was refused before the app received it
