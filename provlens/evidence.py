"""Combine signals into explainable findings - never a bare "fake / real".

Every signal states which hypothesis it supports (edited, generated,
consistent with an untouched capture), how strongly (``strength``, what the
detector measured) and how much that kind of evidence deserves to count
(``weight``, its reliability as measured in docs/evaluation.md or argued in
the docs). The three questions are scored separately with a noisy-OR:

    score = 1 - prod(1 - weight_i * strength_i)

so independent signals reinforce each other, and no pile of weak signals
reaches certainty. The output is three short statements plus the
signal table they come from:

* **Provenance** - what content credentials (C2PA) say, if anything
* **Editing**    - none / weak / moderate / strong evidence of changes
* **Generation** - declared AI generation, or "no declaration"
  (absence is never evidence of authenticity)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

# Reliability priors per signal type (see docs/evaluation.md for the measured ones).
WEIGHTS = {
    "c2pa.tampered": 0.95,
    "c2pa.declared_edit": 0.9,
    "c2pa.declared_ai": 0.95,
    "c2pa.valid": 0.9,
    "meta.edited": 0.6,
    "meta.generated": 0.9,
    "meta.inconsistent": 0.5,
    "meta.consistent": 0.3,
    "qtable.software": 0.4,
    "qtable.camera": 0.3,
    "djpeg.double": 0.55,
    "pixel.region": 0.3,
    "pixel.agreement": 0.55,
    "format.extension": 0.2,
}
CAMERA_BRANDS = ("canon", "nikon", "sony", "fujifilm", "olympus", "om digital", "panasonic", "pentax", "ricoh",
                 "leica", "hasselblad", "sigma")  # dedicated cameras ship their own tables; phones often use libjpeg's


SCORED_MAPS = {"ela", "ghost"}


@lru_cache(maxsize=1)
def pixel_thresholds() -> dict[str, float]:
    """Robust-z a pixel map must exceed to count: the 95th percentile on authentic training images."""
    path = Path(__file__).parent / "data" / "pixel_thresholds.json"
    if path.exists():
        return json.loads(path.read_text())
    return {"ela": 6.0, "noise": 6.0, "ghost": 6.0}


EDIT_ACTIONS = {"c2pa.edited", "c2pa.color_adjustments", "c2pa.cropped", "c2pa.filtered", "c2pa.resized",
                "c2pa.drawing", "c2pa.placed", "c2pa.removed", "c2pa.transcoded", "c2pa.converted", "c2pa.orientation"}


@dataclass
class Signal:
    id: str
    module: str
    title: str
    supports: str  # edited | generated | authentic | neutral | not_applicable
    strength: float
    weight: float
    detail: str

    @property
    def contribution(self) -> float:
        return self.strength * self.weight if self.supports in ("edited", "generated", "authentic", "declared") else 0.0

    def to_json(self) -> dict[str, Any]:
        return {"id": self.id, "module": self.module, "title": self.title, "supports": self.supports,
                "strength": round(self.strength, 3), "weight": self.weight,
                "contribution": round(self.contribution, 3), "detail": self.detail}


@dataclass
class Verdict:
    provenance: str
    editing_level: str
    editing_score: float
    generation: str
    generation_score: float
    authentic_score: float
    limited_signal: bool
    headline: str
    signals: list[Signal] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "provenance": self.provenance, "editing_level": self.editing_level,
            "editing_score": round(self.editing_score, 3), "generation": self.generation,
            "generation_score": round(self.generation_score, 3), "authentic_score": round(self.authentic_score, 3),
            "limited_signal": self.limited_signal, "headline": self.headline,
            "signals": [s.to_json() for s in sorted(self.signals, key=lambda s: -s.contribution)],
        }


def noisy_or(signals: list[Signal], supports: str) -> float:
    p = 1.0
    for s in signals:
        if s.supports == supports:
            p *= 1.0 - min(max(s.contribution, 0.0), 0.99)
    return 1.0 - p


def level(score: float) -> str:
    if score >= 0.75:
        return "strong"
    if score >= 0.5:
        return "moderate"
    if score >= 0.25:
        return "weak"
    return "none"


def _boxes_overlap(a: list[int], b: list[int]) -> bool:
    return not (a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1])


def build_signals(result: dict[str, Any]) -> list[Signal]:
    S: list[Signal] = []
    c2 = result.get("c2pa") or {}
    if c2.get("present"):
        summary = c2.get("summary", "")
        tamper = [s for s in c2.get("statuses", []) if s["kind"] == "failure" and s["scope"] == "active manifest"
                  and s["code"] not in ("signingCredential.untrusted", "signingCredential.expired")]
        hb = c2.get("hard_binding") or {}
        loose = hb.get("match") and hb.get("exclusion_covers_non_manifest")
        real_tamper = [s for s in tamper if not (loose and s["code"] == "assertion.dataHash.mismatch")]
        if real_tamper:
            S.append(Signal("c2pa.tampered", "c2pa", "Content credentials broken", "edited", 1.0, WEIGHTS["c2pa.tampered"],
                            "; ".join(s["explain"] for s in real_tamper)))
        elif loose:
            S.append(Signal("c2pa.loose-binding", "c2pa", "Credentials do not protect all metadata", "neutral", 0.0, 0.0,
                            summary))
        else:
            S.append(Signal("c2pa.valid", "c2pa", "Image unchanged since it was signed", "authentic", 1.0, WEIGHTS["c2pa.valid"],
                            summary))
        actions = (c2.get("active") or {}).get("actions", [])
        edits = [a for a in actions if a.get("action") in EDIT_ACTIONS]
        if edits:
            S.append(Signal("c2pa.declared_edit", "c2pa", "Edits declared in the credentials", "declared", 1.0,
                            WEIGHTS["c2pa.declared_edit"],
                            "The signer declares: " + ", ".join(sorted({a['action'].replace('c2pa.', '') for a in edits}))
                            + ". Declared edits are expected and say what was done."))
        for decl in c2.get("ai_declared", []):
            S.append(Signal("c2pa.declared_ai", "c2pa", "AI generation declared in credentials", "generated", 1.0,
                            WEIGHTS["c2pa.declared_ai"], decl))
    elif c2.get("state") == "error":
        S.append(Signal("c2pa.error", "c2pa", "C2PA check failed", "neutral", 0.0, 0.0,
                        c2.get("summary") or "The C2PA check failed; whether credentials are present is unknown."))
    else:
        S.append(Signal("c2pa.absent", "c2pa", "No content credentials", "neutral", 0.0, 0.0,
                        "Most authentic images carry no C2PA manifest, so its absence is not evidence either way."))

    for f in result.get("metadata", {}).get("findings", []):
        status = f["status"]
        if status in ("edited", "generated", "inconsistent", "consistent"):
            supports = {"edited": "edited", "inconsistent": "edited", "generated": "generated", "consistent": "authentic"}[status]
            key = {"edited": "meta.edited", "inconsistent": "meta.inconsistent", "generated": "meta.generated",
                   "consistent": "meta.consistent"}[status]
            S.append(Signal(f["rule"], "metadata", f["title"], supports, f["strength"], WEIGHTS[key], f["detail"]))
        elif f["rule"] == "M00-stripped":
            S.append(Signal(f["rule"], "metadata", f["title"], "neutral", 0.0, 0.0, f["detail"]))

    jp = result.get("jpeg")
    if jp:
        qt = jp.get("qtables") or {}
        best = qt.get("best") or {}
        make = ((result.get("metadata") or {}).get("summary", {}).get("exif", {}) or {}).get("Make", "")
        make = str(make).lower()
        family = best.get("family")
        if best.get("exact") and family in ("photoshop", "ffmpeg"):
            S.append(Signal("qtable.software", "qtables", f"Tables match {best['source']}", "edited", 0.8,
                            WEIGHTS["qtable.software"], f"Exact match with {best['source']} ({best['quality']}): last saved by that software."))
        elif best.get("exact") and family == "ijg" and any(b in make for b in CAMERA_BRANDS):
            # Not scored: the genuine, Nikon-signed Z 9 sample in the C2PA conformance set uses
            # exactly these standard tables, so "camera file with libjpeg tables" is not a re-encode tell.
            S.append(Signal("qtable.match", "qtables", f"Standard libjpeg tables ({best['quality']}) in a '{make}' file",
                            "neutral", 0.0, 0.0,
                            "Editors and platforms use these tables, but so do some cameras (a genuine Nikon Z 9 "
                            "sample does), so this is not counted as evidence."))
        elif family == "apple" and best.get("exact") and "apple" in make:
            S.append(Signal("qtable.camera", "qtables", "Tables match the Apple encoder named in EXIF", "authentic", 0.6,
                            WEIGHTS["qtable.camera"], "Consistent with an unmodified iPhone/macOS capture or export."))
        elif best:
            S.append(Signal("qtable.match", "qtables", f"Closest encoder: {best['source']} {best['quality']}", "neutral", 0.0, 0.0,
                            f"distance {best['distance']} (0 = identical). Shared tables identify a library, not an app."))
        dj = jp.get("djpeg") or {}
        if dj.get("applicable") and dj.get("double"):
            # 0.5 at the fitted threshold, rising linearly to 1.0 at a score of 1
            t = float(dj.get("threshold") or 0.5)
            strength = 0.5 + 0.5 * (float(dj["probability"]) - t) / max(1e-6, 1 - t)
            S.append(Signal("djpeg.double", "djpeg", "Saved as JPEG more than once", "edited", min(1.0, strength),
                            WEIGHTS["djpeg.double"], dj.get("note", "") + ". Re-saving alone is not manipulation."))
        elif dj.get("applicable"):
            S.append(Signal("djpeg.single", "djpeg", "No double-compression footprint", "neutral", 0.0, 0.0, dj.get("note", "")))
    elif result.get("jpeg_error"):
        S.append(Signal("jpeg.malformed", "jpeg", "JPEG structure damaged", "neutral", 0.0, 0.0,
                        f"{result['jpeg_error']}. Table fingerprinting and the double-compression test were not run; "
                        "damage alone is not evidence of editing."))
    else:
        S.append(Signal("jpeg.na", "jpeg", "JPEG analyses not applicable", "not_applicable", 0.0, 0.0,
                        f"{result.get('format')} has no JPEG quantisation tables: table fingerprinting and the "
                        "double-compression test do not apply (reported as not applicable, not as a pass)."))

    img_info = result.get("image") or {}
    if img_info.get("error"):
        S.append(Signal("image.decode", "pixel", "Pixel data not analysed", "neutral", 0.0, 0.0,
                        f"{img_info['error']}. Pixel maps were not run; damage alone is not evidence of editing."))
    elif img_info.get("maps_skipped"):
        S.append(Signal("image.maps_skipped", "pixel", "Pixel maps skipped", "neutral", 0.0, 0.0,
                        img_info["maps_skipped"] + "."))
    px = result.get("pixel") or {}
    maps = {k: v for k, v in px.items() if isinstance(v, dict) and "regions" in v}
    limits = pixel_thresholds()
    # Only maps whose thresholds were calibrated for this input are scored. The rest
    # stay in the report as pointers: the noise map localised no splice on the labelled
    # set, and every threshold was fitted on JPEG files.
    scored = SCORED_MAPS if result.get("format") == "image/jpeg" else set()
    for name in sorted(set(maps) - scored):
        m = maps[name]
        why = ("thresholds are calibrated on JPEG files only" if name in SCORED_MAPS else
               "it localised no splice on the labelled set (docs/evaluation.md)")
        top = f"strongest region {m['regions'][0]['bbox']} (z {m['regions'][0]['mean_z']}). " if m["regions"] else ""
        S.append(Signal(f"pixel.{name}", "pixel", f"{name.upper()} map shown, not scored", "neutral", 0.0, 0.0,
                        f"{top}Not counted because {why}. {m.get('note', '')}".strip()))
    maps = {k: v for k, v in maps.items() if k in scored}
    flagged = {k: v for k, v in maps.items() if v["regions"] and v["regions"][0]["mean_z"] > limits.get(k, 6.0)}
    for name, m in flagged.items():
        top = m["regions"][0]
        t = limits.get(name, 6.0)
        S.append(Signal(f"pixel.{name}", "pixel", f"{name.upper()} highlights a region", "edited",
                        min(1.0, 0.5 + (top["mean_z"] - t) / (2 * max(t, 1.0))), WEIGHTS["pixel.region"],
                        f"region {top['bbox']} ({top['area_fraction']:.1%} of the image), robust z {top['mean_z']} "
                        f"(threshold {t:.1f}: the 95th percentile on authentic training images). A pointer for an analyst, not proof."))
    for name, m in maps.items():
        if name not in flagged:
            S.append(Signal(f"pixel.{name}", "pixel", f"{name.upper()}: nothing above threshold", "neutral", 0.0, 0.0,
                            m.get("note", "")))
    names = list(flagged)
    agree = set()
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            if any(_boxes_overlap(a["bbox"], b["bbox"]) for a in flagged[names[i]]["regions"][:2]
                   for b in flagged[names[j]]["regions"][:2]):
                agree.update({names[i], names[j]})
    # ELA and noise both respond to flat-versus-textured areas, so their overlap is not
    # independent evidence; on the labelled set every authentic-image "agreement" was
    # exactly that pair. The ghost map is normalised per block and must be one of them.
    if len(agree) >= 2 and "ghost" in agree:
        S.append(Signal("pixel.agreement", "pixel", "Independent pixel maps agree on a region", "edited", 1.0,
                        WEIGHTS["pixel.agreement"], f"{' and '.join(sorted(agree))} flag overlapping areas."))
    if result.get("extension_mismatch"):
        S.append(Signal("format.extension", "format", "Extension does not match content", "edited", 0.5,
                        WEIGHTS["format.extension"], result["extension_mismatch"]))
    return S


def decide(result: dict[str, Any]) -> Verdict:
    signals = build_signals(result)
    edit = noisy_or(signals, "edited")
    gen = noisy_or(signals, "generated")
    auth = noisy_or(signals, "authentic")
    c2 = result.get("c2pa") or {}
    md_empty = (result.get("metadata") or {}).get("empty", True)
    jpeg_ok = bool((result.get("jpeg") or {}).get("djpeg", {}).get("applicable"))
    c2_error = c2.get("state") == "error"
    limited = not c2.get("present") and not c2_error and md_empty and not jpeg_ok and edit < 0.25
    provenance = (c2.get("summary") if c2.get("present") or c2_error else "No content credentials (C2PA).")
    lvl = level(edit)
    generation = ("AI generation declared: " + "; ".join(s.detail for s in signals if s.supports == "generated")[:400]
                  if gen >= 0.5 else "No AI-generation declaration found (absence is not evidence of a camera origin).")
    if limited:
        headline = ("No provenance, limited forensic signal: no content credentials, no metadata, and no format-specific "
                    "statistics to test. Nothing here supports a conclusion either way.")
    else:
        top_edit = [s for s in sorted(signals, key=lambda s: -s.contribution) if s.supports == "edited"][:3]
        parts = []
        if c2.get("present") or c2_error:
            parts.append(provenance.split(". ")[0].rstrip("."))
        if gen >= 0.5:
            parts.append("AI generation is declared")
        declared = [s for s in signals if s.supports == "declared"]
        if declared:
            parts.append(declared[0].detail.split(". ")[0])
        label = {"strong": "Strong", "moderate": "Moderate", "weak": "Weak", "none": "No"}[lvl]
        # Forensics cannot tell which edit a footprint came from, so with declared edits we
        # only ask the reader to compare; we never call the footprints "undeclared".
        compare = " (compare with the declared edits)" if declared and lvl != "none" else ""
        parts.append(f"{label} forensic evidence of editing{compare}" +
                     (": " + "; ".join(s.title.lower() for s in top_edit) if top_edit and lvl != "none" else ""))
        headline = ". ".join(p.rstrip(".") for p in parts) + "."
    return Verdict(provenance, lvl, edit, generation, gen, auth, limited, headline, signals)
