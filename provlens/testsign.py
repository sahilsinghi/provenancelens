"""A throwaway C2PA signing identity, for tests, demos and signing reports.

``make_identity`` creates a root CA and an end-entity signing certificate that
follow the C2PA certificate profile (EC P-256, digitalSignature key usage,
emailProtection EKU, not a CA). Pass the root to ``provlens analyze --trust``
and images signed with it validate as *Trusted*; without it they are *Valid*
but untrusted. Nothing here is suitable for real signing: the keys sit
unencrypted on disk and the certificates name no real organisation.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SOFTWARE = "ProvenanceLens test signer"


@dataclass
class Identity:
    root_pem: Path
    chain_pem: Path  # signer certificate followed by the root
    key_pem: Path


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ProvenanceLens TEST ONLY")])


def make_identity(out: Path, signer_name: str = "ProvenanceLens Test Signer", days: int = 365) -> Identity:
    out.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (x509.CertificateBuilder().subject_name(_name("ProvenanceLens Test Root")).issuer_name(_name("ProvenanceLens Test Root"))
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days * 2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(_name(signer_name)).issuer_name(root.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    ident = Identity(out / "test-root.pem", out / "signer-chain.pem", out / "signer-key.pem")
    ident.root_pem.write_bytes(root.public_bytes(pem))
    ident.chain_pem.write_bytes(leaf.public_bytes(pem) + root.public_bytes(pem))
    ident.key_pem.write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ident.key_pem.chmod(0o600)
    return ident


def load_identity(folder: Path) -> Identity:
    ident = Identity(folder / "test-root.pem", folder / "signer-chain.pem", folder / "signer-key.pem")
    for p in (ident.root_pem, ident.chain_pem, ident.key_pem):
        if not p.exists():
            raise FileNotFoundError(f"{p} is missing; create an identity with `provlens testsign init {folder}`")
    return ident


def _mime(path: Path) -> str:
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def sign(source: Path, dest: Path, ident: Identity, title: str | None = None,
         actions: list[dict[str, Any]] | None = None, assertions: list[dict[str, Any]] | None = None,
         parent: Path | None = None, component: Path | None = None) -> Path:
    """Sign ``source`` into ``dest`` with a manifest declaring ``actions``.

    ``parent`` (optional) is added as the parentOf ingredient, so its own
    credentials, if any, become part of the new manifest's history.
    ``component`` (optional) is added as a componentOf ingredient with a
    ``c2pa.placed`` action, for an asset shown inside the new one.
    """
    import c2pa

    actions = actions or [{"action": "c2pa.created",
                           "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"}]
    if actions[0].get("action") not in ("c2pa.created", "c2pa.opened"):
        # the spec requires the history to start with created or opened
        actions = ([{"action": "c2pa.opened", "parameters": {"ingredientIds": ["parent"]}}] if parent is not None else
                   [{"action": "c2pa.created", "digitalSourceType":
                     "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"}]) + actions
    if component is not None:
        actions = actions + [{"action": "c2pa.placed", "parameters": {"ingredientIds": ["component"]}}]
    for a in actions:
        a.setdefault("softwareAgent", {"name": SOFTWARE})
    manifest = {
        "claim_generator_info": [{"name": "provenancelens", "version": "0.1.0"}],
        "title": title or dest.name,
        "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": actions}}] + list(assertions or []),
    }
    info = c2pa.C2paSignerInfo(b"es256", ident.chain_pem.read_bytes(), ident.key_pem.read_bytes(), None)
    signer = c2pa.Signer.from_info(info)
    builder = c2pa.Builder(json.dumps(manifest))
    try:
        if parent is not None:
            with open(parent, "rb") as fh:
                builder.add_ingredient(json.dumps({"title": parent.name, "relationship": "parentOf", "label": "parent"}),
                                       _mime(parent), fh)
        if component is not None:
            with open(component, "rb") as fh:
                builder.add_ingredient(json.dumps({"title": component.name, "relationship": "componentOf",
                                                   "label": "component"}), _mime(component), fh)
        dest.parent.mkdir(parents=True, exist_ok=True)
        buf = io.BytesIO()
        with open(source, "rb") as src:
            builder.sign(signer, _mime(source), src, buf)
        dest.write_bytes(buf.getvalue())
    finally:
        builder.close()
        signer.close()
    return dest
