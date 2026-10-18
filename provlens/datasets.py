"""Public C2PA test files, pinned to a commit and verified by Git blob hash.

The C2PA conformance samples (CC-BY-SA-4.0) are not redistributed here: they
are fetched into ``.cache/`` at test time and every file must hash to the
blob ID recorded below.
"""

from __future__ import annotations

import hashlib
import urllib.parse
import urllib.request
from pathlib import Path

REPO = "c2pa-org/public-testfiles"
COMMIT = "22beccc075707475b038d8789d0136c009e43143"
LICENSE = "CC-BY-SA-4.0 (fetched at test time, not redistributed)"
PREFIX = "legacy/1.4/image/jpeg/"

# file -> (git blob sha1, expected state, expected failure codes besides signingCredential.untrusted)
# These are the states the c2pa-rs 0.91 validator reports; the samples are signed
# with the C2PA test CA, so none of them can ever be "Trusted".
FILES = {
    "adobe-20220124-A.jpg": ("be277a89ae0a3d12334e6bec6cc9722691a37ba5", "absent", ()),
    "adobe-20220124-C.jpg": ("4b8df5e273c9694f4f9287e2064b66c2d3d33574", "Valid", ()),
    "adobe-20220124-CA.jpg": ("c0fc9ac13155427f8111e7b1d24bdbcebf59a8a3", "Valid", ()),
    "adobe-20220124-CAI.jpg": ("7258f7f7d6e06765eaf29d17f661e962ad343c3f", "Valid", ()),
    "adobe-20220124-CI.jpg": ("83d9340721bba06beb2d210a33d707574abb3ca7", "Valid", ()),
    # valid itself, but its ingredient carried a broken signature when it was used
    "adobe-20220124-CIE-sig-CA.jpg": ("957c373dddf76f12e7efc99e66f4a4a9c51c6c06", "Valid", ()),
    "adobe-20220124-E-clm-CAICAI.jpg": ("57e88677f57f9b13bc64a4d4627b6a7902c80498", "Invalid",
                                        ("assertion.hashedURI.mismatch", "ingredient.manifest.missing")),
    "adobe-20220124-E-dat-CA.jpg": ("6284416b5a226538817f10996245b78f6eaa2b5c", "Invalid", ("assertion.dataHash.mismatch",)),
    "adobe-20220124-E-sig-CA.jpg": ("142f6dc7ba854af189b84ee58859de732aa3efef", "Invalid", ("claimSignature.mismatch",)),
    "adobe-20220124-E-uri-CA.jpg": ("8f57168cc9e41b348f01fb24425ab9c9e6c1da42", "Invalid", ("assertion.hashedURI.mismatch",)),
    "adobe-20220124-I.jpg": ("819e6360553eec1ab599c683279b9ae9dd7c7596", "absent", ()),
    "adobe-20220124-XCA.jpg": ("7cc58ede9c04d18dab486b5cbc8ee704d5ea2cdb", "Invalid", ("assertion.dataHash.mismatch",)),
    # the signing certificate has expired and no trusted timestamp shows it was valid at signing time
    "nikon-20221019-building.jpeg": ("6ac4c2bb6ee9e94c08f955307ce807ccd517cafb", "Invalid", ("signingCredential.expired",)),
    # the dataHash exclusion also covers the Exif segment, which current validators reject
    "truepic-20230212-camera.jpg": ("fa92709828c15574b1e1d3cd1fdb694852df88fd", "Invalid", ("assertion.dataHash.mismatch",)),
}


def cache_dir(root: Path) -> Path:
    return root / ".cache" / "c2pa-public-testfiles" / COMMIT[:12]


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def fetch(root: Path, names: list[str] | None = None) -> list[Path]:
    out = []
    target = cache_dir(root)
    target.mkdir(parents=True, exist_ok=True)
    for name in names or list(FILES):
        sha = FILES[name][0]
        dest = target / name
        if dest.exists() and blob_sha(dest.read_bytes()) == sha:
            out.append(dest)
            continue
        url = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{urllib.parse.quote(PREFIX + name)}"
        req = urllib.request.Request(url, headers={"User-Agent": "provenancelens"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - pinned GitHub raw URL
            data = resp.read()
        if blob_sha(data) != sha:
            raise ValueError(f"{name}: content does not match pinned blob {sha}")
        dest.write_bytes(data)
        out.append(dest)
    return out


def local(root: Path, name: str) -> Path:
    return cache_dir(root) / name
