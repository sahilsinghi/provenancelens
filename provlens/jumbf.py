"""Walk a C2PA manifest store (JUMBF) just far enough to pull out signer certificates.

Manifest *validation* is left to the official c2pa SDK. This module only
locates each manifest's ``c2pa.signature`` box, decodes its COSE_Sign1
structure and returns the ``x5chain`` certificates, so ProvenanceLens can
inspect and explain the X.509 chain independently with ``cryptography``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------
# CBOR (RFC 8949) - decoding only, enough for COSE headers
# --------------------------------------------------------------------------

class CBORError(ValueError):
    pass


@dataclass
class Tagged:
    tag: int
    value: Any


def cbor_decode(data: bytes) -> Any:
    try:
        value, _ = _cbor(data, 0)
    except (IndexError, struct.error, RecursionError) as exc:
        raise CBORError(f"truncated or malformed CBOR: {exc}") from exc
    return value


def _cbor(data: bytes, i: int) -> tuple[Any, int]:
    if i >= len(data):
        raise CBORError("truncated CBOR")
    ib = data[i]
    major, info = ib >> 5, ib & 0x1F
    i += 1
    if info < 24:
        arg = info
    elif info == 24:
        arg, i = data[i], i + 1
    elif info == 25:
        arg, i = struct.unpack(">H", data[i:i + 2])[0], i + 2
    elif info == 26:
        arg, i = struct.unpack(">I", data[i:i + 4])[0], i + 4
    elif info == 27:
        arg, i = struct.unpack(">Q", data[i:i + 8])[0], i + 8
    elif info == 31:
        arg = None  # indefinite length
    else:
        raise CBORError(f"reserved additional info {info}")
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if arg is None:
            chunks = []
            while data[i] != 0xFF:
                chunk, i = _cbor(data, i)
                chunks.append(chunk)
            i += 1
            joined = b"".join(chunks) if major == 2 else "".join(chunks)
            return joined, i
        if i + arg > len(data):
            raise CBORError(f"string of {arg} bytes runs past the end of the data")
        raw = data[i:i + arg]
        return (raw if major == 2 else raw.decode("utf-8", "replace")), i + arg
    if major == 4:
        out = []
        if arg is None:
            while data[i] != 0xFF:
                v, i = _cbor(data, i)
                out.append(v)
            return out, i + 1
        for _ in range(arg):
            v, i = _cbor(data, i)
            out.append(v)
        return out, i
    if major == 5:
        out_map: dict[Any, Any] = {}
        count = arg
        while True:
            if count is None and data[i] == 0xFF:
                return out_map, i + 1
            if count is not None and len(out_map) == count:
                return out_map, i
            k, i = _cbor(data, i)
            v, i = _cbor(data, i)
            out_map[k if not isinstance(k, (list, dict)) else repr(k)] = v
    if major == 6:
        v, i = _cbor(data, i)
        return Tagged(arg, v), i
    if major == 7:
        if info == 20:
            return False, i
        if info == 21:
            return True, i
        if info in (22, 23):
            return None, i
        if info == 25:
            import numpy as np  # half float

            return float(np.frombuffer(struct.pack(">H", arg), dtype=">f2")[0]), i
        if info == 26:
            return struct.unpack(">f", struct.pack(">I", arg))[0], i
        if info == 27:
            return struct.unpack(">d", struct.pack(">Q", arg))[0], i
        return arg, i
    raise CBORError("bad major type")


# --------------------------------------------------------------------------
# JUMBF boxes (ISO/IEC 19566-5)
# --------------------------------------------------------------------------

@dataclass
class Box:
    type: str
    payload: bytes
    label: str | None = None
    children: list["Box"] = field(default_factory=list)


def _boxes(data: bytes) -> list[Box]:
    out, i = [], 0
    while i + 8 <= len(data):
        size, typ = struct.unpack(">I4s", data[i:i + 8])
        header = 8
        if size == 1:
            size = struct.unpack(">Q", data[i + 8:i + 16])[0]
            header = 16
        elif size == 0:
            size = len(data) - i
        if size < header or i + size > len(data):
            break
        payload = data[i + header:i + size]
        box = Box(typ.decode("latin-1"), payload)
        if box.type == "jumb":
            box.children = _boxes(payload)
            if box.children and box.children[0].type == "jumd":
                d = box.children[0].payload
                # 16-byte content-type UUID, toggles byte, then optional NUL-terminated label
                if len(d) > 17 and d[16] & 0x02:
                    end = d.find(b"\x00", 17)
                    box.label = d[17:end if end != -1 else None].decode("utf-8", "replace")
        out.append(box)
        i += size
    return out


def manifest_store_boxes(store: bytes) -> list[Box]:
    return _boxes(store)


def signer_chains(store: bytes) -> dict[str, list[bytes]]:
    """Manifest label -> list of DER certificates (signer first) from COSE x5chain."""
    out: dict[str, list[bytes]] = {}
    for top in _boxes(store):
        if top.label != "c2pa":
            continue
        for manifest in top.children[1:]:
            if manifest.type != "jumb":
                continue
            for part in manifest.children[1:]:
                if part.label != "c2pa.signature":
                    continue
                cbor_box = next((b for b in part.children[1:] if b.type == "cbor"), None)
                if cbor_box is None:
                    continue
                try:
                    out[manifest.label or "?"] = _x5chain(cbor_decode(cbor_box.payload))
                except CBORError:
                    continue
    return out


def _x5chain(cose: Any) -> list[bytes]:
    if isinstance(cose, Tagged):
        cose = cose.value
    if not isinstance(cose, list) or len(cose) < 4:
        return []
    protected = cbor_decode(cose[0]) if cose[0] else {}
    unprotected = cose[1] if isinstance(cose[1], dict) else {}
    for headers in (protected, unprotected):
        chain = headers.get(33) or headers.get("x5chain")
        if chain is None:
            continue
        if isinstance(chain, bytes):
            return [chain]
        return [c for c in chain if isinstance(c, bytes)]
    return []
