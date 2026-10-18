"""C2PA content credentials: validate with the official SDK, then explain.

The c2pa SDK (c2pa-rs via c2pa-python) parses and validates the manifest
store. ProvenanceLens adds three things on top:

1. a plain-English explanation of every validation status code
2. its own checks: an independent recomputation of the hard binding
   (``c2pa.hash.data``) and an X.509 inspection of the signer chain against
   the C2PA certificate profile and the analyst's own trust anchors
3. a summary an analyst can quote: who signed, with what, which edits and
   ingredients are declared, and whether AI generation is *declared*

A missing manifest is reported as exactly that. Most genuine images have
none, so absence is never treated as evidence of fakery.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from provlens import jumbf

# Plain-English meaning of C2PA validation status codes (C2PA spec 2.x, section 15).
EXPLAIN: dict[str, str] = {
    "claimSignature.validated": "The manifest's signature is cryptographically valid.",
    "claimSignature.insideValidity": "The signing certificate was within its validity period when the claim was signed.",
    "claimSignature.mismatch": "The signature does not match the claim: the manifest was altered after it was signed, or signed incorrectly.",
    "claimSignature.missing": "The manifest has no signature, so nothing in it can be trusted.",
    "claimSignature.outsideValidity": "The certificate was not valid at signing time (expired or not yet valid).",
    "signingCredential.trusted": "The signer's certificate chains to a trust anchor you configured.",
    "signingCredential.untrusted": "The signature is valid, but the signer's certificate is not on your trust list, so the signer's identity is not vouched for.",
    "signingCredential.invalid": "The signer's certificate is malformed or breaks the C2PA certificate profile.",
    "signingCredential.revoked": "The signer's certificate has been revoked by its issuer.",
    "signingCredential.expired": "The signer's certificate had expired and no trusted timestamp proves the signature was made while it was valid.",
    "signingCredential.ocsp.skipped": "Online revocation (OCSP) checking was skipped.",
    "signingCredential.ocsp.inaccessible": "The revocation responder could not be reached.",
    "timeStamp.trusted": "A trusted timestamp proves when the manifest was signed.",
    "timeStamp.validated": "The embedded timestamp is valid.",
    "timeStamp.untrusted": "The embedded timestamp is not from a trusted Time-Stamping Authority.",
    "timeStamp.mismatch": "The embedded timestamp does not match the signature.",
    "timeStamp.outsideValidity": "The timestamp authority's certificate was not valid at that time.",
    "assertion.hashedURI.match": "An assertion is exactly as it was when the manifest was signed.",
    "assertion.hashedURI.mismatch": "An assertion (e.g. the edit history or metadata) was changed after signing.",
    "assertion.dataHash.match": "The image bytes are exactly the bytes that were signed (hard binding holds).",
    "assertion.dataHash.mismatch": "The image bytes changed after signing (hard binding broken): pixels or file structure were modified.",
    "assertion.bmffHash.match": "The media bytes are exactly the bytes that were signed.",
    "assertion.bmffHash.mismatch": "The media bytes changed after signing.",
    "assertion.boxesHash.mismatch": "Parts of the file changed after signing.",
    "assertion.missing": "The manifest references an assertion that is not present.",
    "assertion.inaccessible": "An assertion could not be read.",
    "assertion.undeclared": "The manifest contains an assertion it does not list in its claim.",
    "assertion.multipleHardBindings": "More than one hard binding was found; the manifest is malformed.",
    "assertion.action.ingredientMismatch": "An edit action points at an ingredient that does not match.",
    "assertion.action.malformed": "An edit action is malformed.",
    "assertion.cbor.invalid": "An assertion's CBOR encoding is invalid.",
    "assertion.json.invalid": "An assertion's JSON is invalid.",
    "claim.missing": "A referenced claim is missing.",
    "claim.multiple": "More than one claim was found in a manifest.",
    "claim.hardBindings.missing": "The claim does not bind to the image bytes at all.",
    "claim.cbor.invalid": "The claim's CBOR encoding is invalid.",
    "ingredient.manifest.missing": "An ingredient refers to a manifest that is not in the store: part of the edit history was removed.",
    "ingredient.manifest.mismatch": "An ingredient's manifest does not match what the parent recorded.",
    "ingredient.hashedURI.mismatch": "An ingredient record was changed after signing.",
    "ingredient.claimSignature.validated": "An ingredient's own manifest signature is valid.",
    "ingredient.manifest.validated": "An ingredient's own manifest validated.",
    "manifest.inaccessible": "The manifest store could not be read (remote or damaged).",
    "manifest.multipleParents": "A manifest declares more than one parent ingredient.",
    "manifest.update.invalid": "An update manifest is not valid.",
    "algorithm.unsupported": "The manifest uses a cryptographic algorithm this validator does not support.",
    "general.error": "Validation hit an unexpected error.",
}

AI_SOURCE_TYPES = {
    "trainedAlgorithmicMedia": "created by a trained AI model (generative AI)",
    "compositeWithTrainedAlgorithmicMedia": "composite that includes generative-AI content",
    "algorithmicMedia": "created by an algorithm without training data",
    "compositeSynthetic": "composite including synthetic elements",
    "algorithmicallyEnhanced": "algorithmically enhanced",
}
EKU_NAMES = {
    "1.3.6.1.5.5.7.3.4": "emailProtection", "1.3.6.1.5.5.7.3.36": "documentSigning",
    "1.3.6.1.5.5.7.3.8": "timeStamping", "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "1.3.6.1.5.5.7.3.3": "codeSigning", "2.5.29.37.0": "anyExtendedKeyUsage",
    "1.3.6.1.4.1.311.76.59.1.9": "MS C2PA signing", "1.3.6.1.4.1.62558.2.1": "C2PA claim signing",
}
C2PA_OK_EKUS = {"1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.36", "1.3.6.1.4.1.311.76.59.1.9", "1.3.6.1.4.1.62558.2.1"}


@dataclass
class C2PAResult:
    present: bool
    state: str = "absent"  # absent | Trusted | Valid | Invalid | error
    summary: str = ""
    active: dict[str, Any] = field(default_factory=dict)
    manifests: list[dict[str, Any]] = field(default_factory=list)
    statuses: list[dict[str, str]] = field(default_factory=list)
    hard_binding: dict[str, Any] = field(default_factory=dict)
    certificates: list[dict[str, Any]] = field(default_factory=list)
    certificate_findings: list[str] = field(default_factory=list)
    ai_declared: list[str] = field(default_factory=list)
    trust_anchors: list[str] = field(default_factory=list)  # subjects of the anchors validation used
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _recorded_status(ingredient: dict[str, Any]) -> list[str]:
    """Codes the signer recorded about an ingredient when it was used.

    v1/v2 ingredients keep a flat ``validation_status`` list; v3 ingredients keep
    ``validation_results`` with the failures of the ingredient's own manifest.
    """
    codes = [v.get("code") for v in ingredient.get("validation_status", []) or []]
    results = ingredient.get("validation_results") or {}
    codes += [v.get("code") for v in (results.get("activeManifest") or {}).get("failure", []) or []]
    return list(dict.fromkeys(c for c in codes if c))


def _status_list(results: dict[str, Any] | None) -> list[dict[str, str]]:
    out = []
    if not results:
        return out
    for scope, block in results.items():
        if not isinstance(block, dict):
            continue
        for kind in ("success", "informational", "failure"):
            for item in block.get(kind, []) or []:
                code = item.get("code", "")
                out.append({
                    "scope": "active manifest" if scope == "activeManifest" else "ingredient",
                    "kind": kind, "code": code, "sdk": item.get("explanation", ""),
                    "explain": EXPLAIN.get(code, EXPLAIN.get(code.rsplit(".", 1)[0] + ".mismatch", "")) or item.get("explanation", ""),
                    "url": item.get("url", ""),
                })
    for ing in results.get("ingredientDeltas", []) or []:
        for kind in ("informational", "failure"):
            for item in (ing.get("validationDeltas") or {}).get(kind, []) or []:
                code = item.get("code", "")
                out.append({"scope": "ingredient", "kind": kind, "code": code, "sdk": item.get("explanation", ""),
                            "explain": EXPLAIN.get(code, item.get("explanation", "")), "url": item.get("url", "")})
    return out


def _reader(path: Path, trust_pem: str | None):
    import c2pa

    if trust_pem:
        settings = c2pa.Settings.from_dict({"verify": {"verify_trust": True}, "trust": {"trust_anchors": trust_pem}})
        context = c2pa.Context(settings)
        return c2pa.Reader(str(path), context=context)
    return c2pa.Reader(str(path))


def _jpeg_manifest_spans(data: bytes) -> tuple[list[tuple[int, int]], list[tuple[str, int, int]]]:
    """Byte spans of the APP11 JUMBF segments, and of every other segment, in a JPEG."""
    from provlens.jpeg import parse

    jumbf_spans, others = [], []
    try:
        info = parse(data)
    except Exception:  # noqa: BLE001
        return [], []
    for seg in info.segments:
        span = (seg.offset, seg.offset + 2 + seg.length)
        if seg.kind() == "JUMBF (C2PA)":
            jumbf_spans.append(span)
        else:
            others.append((seg.kind(), *span))
    return jumbf_spans, others


def independent_hard_binding(data: bytes, assertion: dict[str, Any]) -> dict[str, Any]:
    """Recompute c2pa.hash.data ourselves: hash every byte outside the exclusions.

    Also checks *what* the exclusions cover. An exclusion should remove only the
    manifest store; one that also swallows other segments (Exif, XMP) leaves those
    bytes outside the signature, so they could be edited without detection.
    """
    alg = assertion.get("alg", "sha256")
    exclusions = sorted((int(e["start"]), int(e["length"])) for e in assertion.get("exclusions", []))
    h = hashlib.new({"sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}.get(alg, "sha256"))
    pos = 0
    for start, length in exclusions:
        h.update(data[pos:start])
        pos = start + length
    h.update(data[pos:])
    computed = h.digest()
    expected = base64.b64decode(assertion.get("hash", ""))
    unprotected: list[str] = []
    if data[:2] == b"\xff\xd8":
        _, others = _jpeg_manifest_spans(data)
        for start, length in exclusions:
            end = start + length
            for kind, a, b in others:
                if a < end and b > start:
                    unprotected.append(f"{kind} segment (bytes {a}..{b - 1})")
            if start < 2:
                unprotected.append("the JPEG start-of-image marker")
    return {"checked": True, "alg": alg, "exclusions": [{"start": s, "length": n} for s, n in exclusions],
            "expected": expected.hex(), "computed": computed.hex(), "match": computed == expected,
            "exclusion_covers_non_manifest": unprotected}


def inspect_chain(chain: list[bytes], anchors: list[Any]) -> tuple[list[dict[str, Any]], list[str]]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    certs = []
    findings = []
    parsed = [x509.load_der_x509_certificate(d) for d in chain]
    for i, c in enumerate(parsed):
        try:
            eku = [EKU_NAMES.get(o.dotted_string, o.dotted_string)
                   for o in c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
            eku_oids = {o.dotted_string for o in c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value}
        except x509.ExtensionNotFound:
            eku, eku_oids = [], set()
        try:
            bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            bc = False
        key = c.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key_desc = f"RSA {key.key_size}"
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key_desc = f"EC {key.curve.name}"
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key_desc = "Ed25519"
        else:
            key_desc = type(key).__name__
        certs.append({
            "role": "signer" if i == 0 else ("root" if c.issuer == c.subject else "intermediate"),
            "subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
            "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(),
            "serial": str(c.serial_number), "key": key_desc, "eku": eku, "is_ca": bc,
            "sha256": c.fingerprint(hashes.SHA256()).hex(),
        })
        if i == 0:
            if bc:
                findings.append("The signing certificate is a CA certificate, which the C2PA certificate profile forbids.")
            if eku_oids and not eku_oids & C2PA_OK_EKUS:
                findings.append(f"The signing certificate's extended key usages ({', '.join(eku)}) do not include one the C2PA profile allows.")
            if "2.5.29.37.0" in eku_oids:
                findings.append("The signing certificate allows anyExtendedKeyUsage, which the C2PA profile forbids.")
            if "FOR TESTING" in c.subject.rfc4514_string().upper() or "TEST" in c.issuer.rfc4514_string().upper():
                findings.append("This is a test certificate: the credentials are well-formed, but they identify no real organisation.")
            now = datetime.now(timezone.utc)
            if c.not_valid_after_utc < now:
                findings.append(f"The signing certificate expired on {c.not_valid_after_utc.date()}. Unless a trusted timestamp proves "
                                "the image was signed earlier, validators treat the signature as expired.")
    if anchors and parsed:
        anchor_fps = {a.fingerprint(hashes.SHA256()) for a in anchors}
        anchor_subjects = {a.subject for a in anchors}
        chained = any(c.fingerprint(hashes.SHA256()) in anchor_fps or c.issuer in anchor_subjects for c in parsed)
        if not chained:
            findings.append("None of the certificates chain to your trust anchors.")
    return certs, findings


def _ai_declarations(manifest: dict[str, Any]) -> list[str]:
    out = []
    for a in manifest.get("assertions", []):
        label = a.get("label", "")
        data = a.get("data") or {}
        if label.startswith("c2pa.actions"):
            for act in data.get("actions", []):
                dst = str(act.get("digitalSourceType", ""))
                for key, desc in AI_SOURCE_TYPES.items():
                    if dst.endswith("/" + key):
                        out.append(f"action '{act.get('action')}' declares digitalSourceType {key}: {desc}")
                sa = act.get("softwareAgent")
                name = sa.get("name") if isinstance(sa, dict) else sa
                if name and any(t in str(name).lower() for t in ("firefly", "dall", "openai", "midjourney", "stable diffusion", "imagen", "gemini")):
                    out.append(f"action '{act.get('action')}' was performed by generative tool '{name}'")
        if label.startswith("c2pa.training-mining"):
            continue
    gen = " ".join(str(g.get("name", "")) for g in manifest.get("claim_generator_info", []) or []) + " " + str(manifest.get("claim_generator", ""))
    if any(t in gen.lower() for t in ("openai", "dall", "firefly", "bing image creator", "midjourney")):
        out.append(f"the claim generator is a generative-AI service ('{gen.strip()}')")
    return out


def check(path: Path, trust_anchor_paths: list[Path] | None = None) -> C2PAResult:
    import c2pa

    data = Path(path).read_bytes()
    trust_pem = None
    anchors = []
    if trust_anchor_paths:
        from cryptography import x509

        pems = []
        for p in map(Path, trust_anchor_paths):
            if not p.exists():
                raise FileNotFoundError(f"trust anchor {p} does not exist")
            for f in ([p] if p.is_file() else sorted(p.glob("*.pem"))):
                text = f.read_text()
                pems.append(text)
                anchors.extend(x509.load_pem_x509_certificates(text.encode()))
        trust_pem = "\n".join(pems)
    try:
        reader = _reader(path, trust_pem)
    except Exception as exc:  # noqa: BLE001 - the SDK raises typed errors per failure
        name = type(exc).__name__
        if "NotFound" in name or "no JUMBF" in str(exc):
            return C2PAResult(present=False, state="absent",
                              summary="No content credentials. Most genuine images have none (cameras, phones and "
                                      "platforms rarely add them, and social platforms strip them), so this is not evidence of manipulation.")
        return C2PAResult(present=True, state="error", error=f"{name}: {exc}",
                          summary="A manifest store is present but could not be read; treat as unverified.")
    try:
        state = str(reader.get_validation_state() or "")
        manifest_store = json.loads(reader.json())
        detailed = json.loads(reader.detailed_json())
        statuses = _status_list(reader.get_validation_results())
        active_label = manifest_store.get("active_manifest")
        store_bytes = io.BytesIO()
        try:
            reader.resource_to_stream(f"self#jumbf=/c2pa/{active_label}/c2pa.signature", store_bytes)
        except Exception:  # noqa: BLE001
            pass
    finally:
        reader.close()
    res = C2PAResult(present=True, state=state or "Unknown", statuses=statuses)
    manifests = manifest_store.get("manifests", {})
    active = manifests.get(active_label, {})
    sig = active.get("signature_info", {})
    actions = []
    for a in active.get("assertions", []):
        if a.get("label", "").startswith("c2pa.actions"):
            for act in (a.get("data") or {}).get("actions", []):
                sa = act.get("softwareAgent")
                actions.append({"action": act.get("action"), "when": act.get("when"),
                                "software": sa.get("name") if isinstance(sa, dict) else sa,
                                "digital_source_type": str(act.get("digitalSourceType", "")).rsplit("/", 1)[-1] or None})
    res.active = {
        "label": active_label, "title": active.get("title"), "format": active.get("format"),
        "claim_generator": active.get("claim_generator") or ", ".join(
            f"{g.get('name')} {g.get('version', '')}".strip() for g in active.get("claim_generator_info", []) or []),
        "signer": {"issuer": sig.get("issuer"), "common_name": sig.get("common_name"), "alg": sig.get("alg"),
                   "time": sig.get("time"), "serial": sig.get("cert_serial_number")},
        "actions": actions,
        "assertions": [a.get("label") for a in active.get("assertions", [])],
        "ingredients": [{"title": i.get("title"), "relationship": i.get("relationship"),
                         "manifest": i.get("active_manifest"), "format": i.get("format"),
                         "recorded_status": _recorded_status(i)}
                        for i in active.get("ingredients", [])],
    }
    for label, m in manifests.items():
        res.manifests.append({
            "label": label, "title": m.get("title"), "active": label == active_label,
            "signer": (m.get("signature_info") or {}).get("common_name"),
            "issuer": (m.get("signature_info") or {}).get("issuer"),
            "ingredients": [{"title": i.get("title"), "relationship": i.get("relationship"), "manifest": i.get("active_manifest")}
                            for i in m.get("ingredients", [])],
        })
    hard = ((detailed.get("manifests", {}).get(active_label, {}) or {}).get("assertion_store", {}) or {}).get("c2pa.hash.data")
    if isinstance(hard, dict) and "hash" in hard:
        res.hard_binding = independent_hard_binding(data, hard)
    else:
        res.hard_binding = {"checked": False, "reason": "no c2pa.hash.data assertion (other binding types are checked by the SDK only)"}
    chains = jumbf.signer_chains(store_bytes.getvalue()) if store_bytes.getvalue() else {}
    if chains.get(active_label):
        res.certificates, res.certificate_findings = inspect_chain(chains[active_label], anchors)
    res.ai_declared = _ai_declarations(active)
    failures = [s for s in statuses if s["kind"] == "failure" and s["scope"] == "active manifest"]
    tamper = [s for s in failures if s["code"] not in ("signingCredential.untrusted", "signingCredential.expired")]
    signer = sig.get("common_name") or sig.get("issuer") or "an unknown signer"
    hb = res.hard_binding
    loose_exclusion = bool(hb.get("checked") and hb.get("match") and hb.get("exclusion_covers_non_manifest"))
    if loose_exclusion:
        for s in statuses:
            if s["code"] == "assertion.dataHash.mismatch":
                s["explain"] = ("The validator rejects the hard binding because its exclusion range covers more than the "
                                "manifest store (" + ", ".join(hb["exclusion_covers_non_manifest"]) + "). The image data "
                                "itself still hashes to the signed value; the excluded bytes are simply unprotected.")
    if tamper:
        reasons = []
        for s in tamper:
            if s["code"] == "assertion.dataHash.mismatch" and loose_exclusion:
                continue
            reasons.append(EXPLAIN.get(s["code"], s["code"]))
        if reasons:
            res.summary = "Content credentials are present but INVALID: " + "; ".join(reasons)
        else:
            res.summary = (f"Content credentials signed by {signer} are rejected by the validator: the signed hash "
                           "excludes more than the manifest store.")
    elif state.lower() == "trusted":
        res.summary = f"Valid content credentials, signed by {signer} (trusted)."
    elif any(s["code"] == "signingCredential.expired" for s in failures):
        res.summary = f"Credentials are intact, but the signing certificate of {signer} has expired and no trusted timestamp covers it."
    else:
        res.summary = (f"Valid content credentials signed by {signer}, but the signer is not on your trust list: "
                       "the edit history is intact, the identity is unverified.")
    if hb.get("checked") and not hb.get("match"):
        res.summary += " ProvenanceLens's own recomputation of the hard binding also does not match."
    elif loose_exclusion:
        res.summary += (" ProvenanceLens recomputed the hash itself: the image data is unchanged, but the exclusion also "
                        "covers " + ", ".join(hb["exclusion_covers_non_manifest"]) + ", so those bytes (the camera "
                        "metadata) are not protected and could have been edited after signing without detection.")
    bad_ingredients = [i for i in res.active.get("ingredients", [])
                       if any(c and c.split(".")[-1] in ("mismatch", "missing", "invalid", "revoked") for c in i["recorded_status"])]
    for ing in bad_ingredients:
        res.summary += (f" Ingredient '{ing['title']}' ({ing['relationship']}) already had invalid credentials when it was "
                        f"used ({', '.join(ing['recorded_status'])}).")
    res.trust_anchors = [a.subject.rfc4514_string() for a in anchors]
    return res
