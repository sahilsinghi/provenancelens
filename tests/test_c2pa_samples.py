"""The C2PA conformance samples: every state and failure is reported and explained."""

from __future__ import annotations

import pytest

from provlens import c2pa_check, datasets, jumbf, report
from provlens.analyze import analyse

pytestmark = pytest.mark.network


@pytest.mark.parametrize("name", sorted(datasets.FILES))
def test_sample_state(public_samples, name):
    _, state, expected_failures = datasets.FILES[name]
    r = c2pa_check.check(public_samples / name, None)
    assert r.state == state
    if state == "absent":
        assert not r.present
        return
    failures = {s["code"] for s in r.statuses if s["kind"] == "failure"} - {"signingCredential.untrusted"}
    assert failures == set(expected_failures)
    for s in r.statuses:
        if s["kind"] == "failure":
            assert s["explain"], f"{s['code']} has no plain-language explanation"
    # the Adobe samples are signed by the C2PA test CA and must be flagged as test credentials;
    # the Nikon and Truepic ones carry production certificates
    is_test = any("test certificate" in f for f in r.certificate_findings)
    assert is_test == name.startswith("adobe-")


def test_hard_binding_recomputed_independently(public_samples):
    good = c2pa_check.check(public_samples / "adobe-20220124-CA.jpg", None)
    assert good.hard_binding["checked"] and good.hard_binding["match"]
    bad = c2pa_check.check(public_samples / "adobe-20220124-E-dat-CA.jpg", None)
    assert bad.hard_binding["checked"] and bad.hard_binding["match"] is False


def test_loose_exclusion_is_explained(public_samples):
    r = c2pa_check.check(public_samples / "truepic-20230212-camera.jpg", None)
    # our recomputation matches, yet the validator rejects it: the exclusion covers Exif too
    assert r.hard_binding["match"] is True
    assert r.hard_binding["exclusion_covers_non_manifest"]
    assert "excludes more than the manifest store" in r.summary
    assert "not protected" in r.summary


def test_expired_certificate_is_explained(public_samples):
    r = c2pa_check.check(public_samples / "nikon-20221019-building.jpeg", None)
    expired = next(s for s in r.statuses if s["code"] == "signingCredential.expired")
    assert "expired" in expired["explain"].lower() or "validity" in expired["explain"].lower()


def test_invalid_ingredient_is_surfaced(public_samples):
    r = c2pa_check.check(public_samples / "adobe-20220124-CIE-sig-CA.jpg", None)
    assert r.state == "Valid"
    assert "already had invalid credentials" in r.summary
    assert "claimSignature.mismatch" in r.summary


def test_signer_chain_extracted_from_jumbf(public_samples):
    import c2pa

    with c2pa.Reader(str(public_samples / "adobe-20220124-CA.jpg")) as reader:
        import io
        import json

        label = json.loads(reader.json())["active_manifest"]
        buf = io.BytesIO()
        reader.resource_to_stream(f"self#jumbf=/c2pa/{label}/c2pa.signature", buf)
    chains = jumbf.signer_chains(buf.getvalue())
    assert label in chains and len(chains[label]) >= 2
    certs = c2pa_check.check(public_samples / "adobe-20220124-CA.jpg", None).certificates
    assert certs[0]["role"] == "signer" and "C2PA Signer" in certs[0]["subject"]


def test_ingredient_graph_rendered(public_samples):
    r = analyse(public_samples / "adobe-20220124-CAI.jpg", maps=False)
    svg = report.chain_svg(r["c2pa"])
    assert svg.startswith("<svg") and svg.count("<rect") >= 2
