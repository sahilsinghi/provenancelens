# Evaluation

ProvenanceLens makes three kinds of claims, and each is tested differently:

| Claim | How it is tested |
|---|---|
| C2PA validation is correct and explained | 14 public C2PA conformance files (pinned by commit and blob hash) plus images the test suite signs and tampers with itself |
| Metadata rules fire when they should | Unit tests that write the exact EXIF/XMP/PNG fields each rule looks for |
| Forensic detectors are useful and their thresholds honest | A labelled set with known ground truth, **split by source image** so no crop of a test photo is seen during fitting |

Everything below is reproduced by:

```bash
provlens datasets fetch          # C2PA samples into .cache/
provlens evaluate --fit          # labelled set, refit, held-out report -> .cache/eval/report.json
pytest -m "slow or not slow"     # includes a test that re-runs the evaluation and asserts these numbers
```

## 1. C2PA conformance samples

Files from [`c2pa-org/public-testfiles`](https://github.com/c2pa-org/public-testfiles) at commit `22beccc0`, validated by c2pa-rs 0.91 and cross-checked by ProvenanceLens's own hard-binding recomputation and certificate inspection.

| File | State | Failures (besides "untrusted") | What ProvenanceLens says |
|---|---|---|---|
| adobe-20220124-A.jpg, I.jpg | absent | – | No credentials, which is not evidence either way |
| adobe-20220124-C / CA / CAI / CI | Valid | – | Edit history intact, but the signer is the C2PA **test** CA (flagged as a test certificate) |
| adobe-20220124-CIE-sig-CA | Valid | – | Valid itself, but its ingredient *E-sig-CA* already had a broken signature when it was used |
| adobe-20220124-E-dat-CA, XCA | Invalid | `assertion.dataHash.mismatch` | Image bytes changed after signing; our own recomputation agrees |
| adobe-20220124-E-sig-CA | Invalid | `claimSignature.mismatch` | The manifest's signature does not verify |
| adobe-20220124-E-uri-CA | Invalid | `assertion.hashedURI.mismatch` | An assertion was altered after signing |
| adobe-20220124-E-clm-CAICAI | Invalid | `assertion.hashedURI.mismatch`, `ingredient.manifest.missing` | Altered assertion and a missing ingredient manifest |
| nikon-20221019-building.jpeg | Invalid | `signingCredential.expired` | Image intact (our recomputation matches), but the Nikon signing certificate has expired and no trusted timestamp proves it was valid at signing time |
| truepic-20230212-camera.jpg | Invalid | `assertion.dataHash.mismatch` | **Not tampering**: our recomputation *matches*, but the hash's exclusion range also covers the Exif segment, which current validators reject. ProvenanceLens explains that the camera metadata is unprotected |

The Truepic file is why ProvenanceLens recomputes the hard binding itself: the SDK's verdict is right but its status code ("data hash mismatch") would mislead a reader into thinking pixels changed.

Signed-by-us tests (`tests/test_spec_cases.py`):

- An image signed with a throwaway CA validates as **Trusted** when that CA is passed with `--trust`, and as **Valid but untrusted** without it.
- Its edit history (an `opened` + `cropped` + `color_adjustments` manifest whose `parentOf` ingredient is the earlier signed version) is shown and drawn as a graph.
- **One flipped bit** in the compressed scan data gives `Invalid` / `assertion.dataHash.mismatch`, and our recomputation independently disagrees with the signed hash.

## 2. The labelled forensic set

**Sources.** 13 photographs and textures bundled with scikit-image (public domain / CC0): astronaut, coffee, chelsea, rocket, immunohistochemistry, hubble_deep_field, camera, brick, grass, gravel, coins, moon, page. Each is downscaled 2× with Lanczos, so any JPEG grid from its own past is destroyed, and then randomly cropped to at most 320×320.

**Split.** `coffee`, `camera`, `grass` and `hubble_deep_field` are held out. Thresholds and the double-JPEG model are fitted on the other 9 sources only. All numbers below are on the held-out sources (24 images per kind; 4 for `ai_declared` and `stripped`).

**Kinds** (416 images, seed 2026):

| Kind | Construction | Should be flagged? |
|---|---|---|
| authentic | one save at q75–95 | no |
| platform | save at q92, resize to 80%, save at q70–80 (a benign re-upload) | no |
| double_up | save at q55–80, re-save at a quality ≥10 higher (download, edit, export) | it was re-saved, which is not manipulation |
| double_down | save at q85–95, re-save lower at q60–85 (camera → platform) | it was re-saved, which is not manipulation |
| splice | a patch (¼–⅓ of each side) from another source pasted into a downloaded JPEG (q65–80), exported at q85–95; the patch is recompressed at q40–60, made noisier or resampled | **yes**, and its box is recorded |
| ai_declared | IPTC `DigitalSourceType = trainedAlgorithmicMedia` in XMP | generation must be reported |
| stripped | PNG without any metadata | "limited signal" |

### Double-compression detector

The DCT coefficients of the luma plane, divided by the file's own table, are compared with a *calibrated* copy computed 4 pixels off the block grid (Fridrich's calibration: off-grid blocks carry no quantisation footprint). That gives five statistics:
- L1 histogram distance over the first 10 AC frequencies and over the next 10
- the worst single frequency
- the share of expected bins that are empty
- the shift in the coefficients' first-digit (Benford) distribution

They feed a logistic regression with five weights, fitted on authentic + platform (negative) against double_up (positive). The threshold is the score that 1% of training negatives reach, plus 0.05 (it came out at **0.20**).

| Held-out kind | Flagged as saved twice | 95% interval |
|---|---|---|
| authentic | 0 / 24 = **0%** | 0–13.8% |
| platform re-upload | 0 / 24 = **0%** | 0–13.8% |
| double_up (second save at higher quality) | 24 / 24 = **100%** | 86.2–100% |
| splice (exported at higher quality) | 23 / 24 = **95.8%** | 79.8–99.3% |
| double_down (second save at lower quality) | 0 / 24 = **0%** | 0–13.8% |

**Known blind spot:** a second save at *lower* quality is invisible to these features, and this is the most common real-world history (camera JPEG, then platform recompression). The report says so in every JPEG analysis rather than presenting "not detected" as a pass.

### Pixel maps

Each map is reduced to 16×16 (noise: 32×32) blocks and scored with a robust z-score (median/MAD). A region counts when its mean z exceeds the 95th percentile of the same score on authentic + platform **training** images, floored at the region detector's own cut-off. "Localised" means the strongest region overlaps the true splice box.

| Map | Threshold z | False alarms (held-out authentic + platform) | Splice localised (held-out) | Scored? |
|---|---|---|---|---|
| ELA | 3.5 | 0 / 48 = **0%** (0–7.4%) | 14 / 24 = **58.3%** (38.8–75.5%) | yes, weight 0.3 |
| JPEG ghost | 3.0 | 4 / 48 = **8.3%** (3.3–19.6%) | 21 / 24 = **87.5%** (69.0–95.7%) | yes, weight 0.3 |
| Noise level | 15.0 | 0 / 48 | 0 / 24 = **0%** | **no**: shown as a pointer only |
| Agreement (ghost + ELA overlap) | – | – | – | yes, weight 0.55 |

### Whole-pipeline verdicts (held-out)

| Kind | none | weak | moderate | strong |
|---|---|---|---|---|
| authentic | 23 | 1 | 0 | 0 |
| platform | 24 | 0 | 0 | 0 |
| double_up | 0 | 3 | 21 | 0 |
| double_down | 20 | 4 | 0 | 0 |
| splice | 1 | 0 | 9 | 14 |

- **Splice vs benign (authentic + platform), "moderate or stronger" as positive:** recall 23/24 = 95.8% (79.8–99.3%), specificity 48/48 = 100% (92.6–100%).
- **AI declaration** recognised in 4/4. **Stripped PNG** reported as "no provenance, limited forensic signal" in 4/4.
- double_up lands on *moderate* because it really was saved twice and the report says exactly that; the explanation adds "Re-saving alone is not manipulation". The verdict answers "is there evidence of editing", not "is this fake".

## 3. What calibration changed (and why it matters)

Building the evaluation exposed three problems in the first version. Each one would have shipped a detector that looks fine on a headline number.

1. **Double-JPEG at a fixed 0.5.** The first model was trained with *double_down* as a positive class. Those images are statistically almost identical to single saves, so the regression pushed every score towards 0.5. The held-out headline (4% false alarms) looked acceptable, but on the training sources the same threshold flagged **26% of authentic** and **56% of platform** images. Training only on separable classes and *fitting* the threshold took both to 0%.
2. **ELA at its own quality.** ELA re-saves at q90. For an image last saved at q90, the re-save is nearly idempotent, the error map is ~0, the MAD collapses, and rounding noise becomes z-scores in the millions. Across 12 sources at two sizes, **50–75% of single-save q90 images** raised an ELA alarm. ELA now re-saves at q80 when the image's estimated quality is within ±2 of 90. In that probe single-save false alarms fell from 11.3% to 1.8%, and splice localisation was unchanged at 25/72. On the held-out set they fell from 6.2% to 0%.
3. **Correlated "agreement".** ELA and the noise map both respond to flat-versus-textured areas (a blue sky next to a rocket). Their overlap is not independent evidence, and on the labelled set every authentic-image "agreement" was exactly that pair. Agreement now requires the ghost map, which keeps 36 of 37 splice agreements.

## 4. Limits

- **Synthetic manipulations, small images.** Splices are pasted rectangles in crops of at most 320 px, made with one encoder family (libjpeg via Pillow). Real edits are blended, feathered, retouched and exported by Photoshop or phone apps at 12+ megapixels. Expect lower recall and different false-alarm rates on real casework. Public forensic datasets (CASIA v2, Columbia, IMD2020) would be the next step; they are not redistributed here because of their licences.
- **Small held-out counts.** 24 images per kind give wide intervals (shown above). A 0% false-alarm rate on 48 images is consistent with a true rate of up to 7.4%.
- **Weights are priors.** The thresholds and the double-JPEG model are fitted; the evidence weights (0.3, 0.55, 0.9, …) are reliability priors chosen by hand and documented in `provlens/evidence.py`. The noisy-OR combination assumes the signals are independent, which is only approximately true. The agreement rule exists because it was badly false in one case.
- **No generative-AI detector.** Generation is reported only when declared (C2PA, IPTC, embedded generator parameters). See [the blog post](why-there-is-no-reliable-fake-image-detector.md) for why.
- **Metadata can be forged** in minutes; contradictions are informative, a clean result is not.
- **C2PA trust** depends on the trust list you pass. Without `--trust`, valid manifests are reported as "valid but untrusted", which is correct but easy to misread.
