# Why there is no reliable fake-image detector, and what to do instead

*Notes from building [ProvenanceLens](../README.md), an image verifier that deliberately has no "fake score".*

Everyone who verifies images for a living gets the same question: *is this real?* The tempting product answers it with one number, "87% likely AI-generated", and the number is the problem. Here is why I did not build that, and what the tool does instead.

## "Fake" is not a property of pixels

The most damaging images in circulation are mostly not generated or edited at all. They are real photographs with a false caption: last year's flood, a different city, a protest from another country. No pixel classifier can see a caption.

The reverse also holds. Almost every published photograph has been edited: cropped, exposure-corrected, sharpened, resized, re-encoded. "Edited" is not "fake", and a detector that flags editing will flag nearly everything.

So the useful questions are narrower:

1. **Where did it come from?** Who says they made it, and can that be checked?
2. **Has it changed since then,** and is there evidence of how?
3. **Does anyone declare that AI generated it?**

None of these is "is it fake", and all three can be answered with evidence that a reader can check.

## Why classifiers keep failing

**They learn the generator, not the concept.** A detector trained on one family of generators learns that family's fingerprints: upsampling artefacts, spectral peaks, colour statistics. A new model architecture, a new sampler or a new upscaler shifts those fingerprints. Accuracy measured on yesterday's generators says little about tomorrow's.

**The internet destroys the evidence.** Platforms resize and recompress every upload. The subtle statistics that separate generated from captured images are exactly what a quality-75 JPEG re-encode throws away. A detector that works on pristine PNGs from the generator often degrades badly on the screenshot of a repost of a repost, which is what you are actually given.

**Base rates make confident errors expensive.** Most images an investigator sees are genuine. A detector with a 5% false-positive rate, run over a thousand genuine images, accuses fifty of them. Calling a real photo of a real atrocity "AI-generated" is not a harmless mistake: it hands a ready-made denial to whoever wants one.

**Detectors become training signal.** Any public detector is a free discriminator. Generators, and people evading moderation, optimise against it.

## Even transparent forensics fail quietly

ProvenanceLens uses classic, explainable forensics: compression history, error-level analysis, JPEG ghosts. I calibrated each one on a labelled set split by source image, and the calibration was the most instructive part of the project. Three of my first-draft detectors looked fine on the headline number and were wrong underneath.

- **The double-compression detector** reported 4% false alarms on its held-out images. On the *other* source photos, the same threshold flagged 26% of untouched images and 56% of benign re-uploads. I had trained it to find a pattern that barely exists: a second save at lower quality, which is the most common real history of any photo. That pushed every score towards 0.5. Retrained on what the features can actually see, with a threshold fitted at a fixed false-alarm rate, it now flags 0% of untouched images and 100% of higher-quality re-saves. It also reports, every time, that it is blind to lower-quality ones.
- **Error-level analysis** re-saves the image at quality 90 and maps what changes. For an image that was *already* saved at 90, almost nothing changes. The spread of the error map collapses, and rounding noise turns into z-scores in the millions. Half to three quarters of untouched q90 images raised an alarm. The fix (re-save at a different quality) is one line. Finding it took a sample image that happened to have been saved at exactly the wrong quality.
- **"Two maps agree"** sounds like strong evidence. But ELA and the noise map both react to a flat sky next to a textured object, so their agreement was correlated, not independent. Every false "agreement" on genuine images was that pair.

None of these failures shows up as an error message. Each produces a confident, plausible, wrong result. A black-box classifier has the same failure modes, plus the fact that you cannot see them.

## What to do instead

### 1. Check provenance first, and read it precisely

[C2PA content credentials](https://c2pa.org) attach a signed manifest to a file. It records who signed it, what tools touched it, which earlier files went into it, and a hash binding the manifest to the exact bytes. A growing number of cameras, editing tools and image generators write them. This is *positive*, cryptographically checkable evidence, which is far more than a classifier can offer. But it has to be read carefully:

- **Valid is not trusted.** A valid signature from an unknown certificate proves the history is intact, not who made it. ProvenanceLens keeps "Valid" and "Trusted" apart and says which trust list it used.
- **Invalid is not always tampering.** One public sample, a 2023 camera image, fails validation with "data hash mismatch". The pixels never changed: its hash excludes the Exif block as well as the manifest, and current validators reject that. ProvenanceLens recomputes the hash itself and explains the difference: the camera metadata in that file is unprotected, and that is the finding.
- **Absent proves nothing.** Credentials are stripped by most platforms and by a screenshot. Most genuine images have none.
- **Credentials describe the file, not the scene.** A perfectly signed photo can still be staged or mis-captioned.

### 2. Treat forensics as pointers, with their error rates attached

Compression history, metadata contradictions and ghost maps are useful. They work best as *questions for an analyst*: "this region was compressed differently; why?" Every signal in a ProvenanceLens report says what was measured, the threshold it crossed, how that threshold was set and how much it counts. The verdict is a transparent noisy-OR over those signals, so the reader can disagree with any line of it.

### 3. Report declared AI use, do not guess it

ProvenanceLens reports AI generation when it is *declared*: a C2PA `trainedAlgorithmicMedia` source type, an IPTC field, a generator's own embedded parameters. When nothing is declared, it says so and adds that absence is not evidence of a camera origin. That sentence is less satisfying than a percentage, and it is true.

### 4. Do the rest the way verification has always been done

Find the earliest copy, reverse-search it, compare it with other angles of the same event, check the weather and shadows, ask the person who posted it. Tools can make the file's own evidence legible. Whether the picture means what someone claims is still a question about the world, not about the pixels.

---

*The calibration numbers above come from a synthetic labelled set (pasted rectangles in images of at most 320 px, made with one JPEG encoder). Full details and limits are in [evaluation.md](evaluation.md).*
