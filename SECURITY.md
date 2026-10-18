# Security

Every file ProvenanceLens analyses is untrusted input. It may be crafted to crash the tool, exhaust memory, inject script into the report, or abuse the external programs it calls.

| Concern | How it is handled |
|---|---|
| Malformed files | Each stage (C2PA, JPEG structure, metadata, pixel decode, maps) fails into the report as an explained, neutral signal instead of aborting. A mutation fuzz of 1,000 damaged JPEG/PNG/C2PA files gives 0 crashes and 0 hangs, including report rendering. |
| Decompression bombs | Image size is read from the header first. Images above 120 MP are not decoded; above 50 MP the pixel maps and double-JPEG statistics are skipped. The EXIF-thumbnail comparison decodes only a ≤1024 px preview. |
| XML in XMP | Parsing starts at `<x:xmpmeta>`, so no DOCTYPE or entity declarations reach the parser (no XXE, no entity expansion). |
| Script in reports | Templates autoescape every value, the C2PA graph SVG is escaped, and reports carry a CSP (`default-src 'none'; img-src data:`) that allows no script at all. |
| External programs | ffmpeg/ffprobe get absolute `file:` paths and `-protocol_whitelist file`, so a file name can't act as a protocol (`concat:`, `http:`) or an option, and a container can't pull in other media. exiftool gets absolute paths. |

## `provlens serve`

The upload page has **no authentication**. It is meant for your own machine:
- Binds to `127.0.0.1` by default.
- When bound to loopback, accepts only loopback `Host` headers, which blocks DNS rebinding from a web page.
- Binding anywhere else requires `--allowed-host`.
- Request bodies are counted while streaming and cut off at the limit (`--max-mb`, default 40) before anything is written to disk.
- Analyses run in worker threads, at most two at a time.
- Uploads go to private temporary files that are deleted right after analysis.
- Responses carry `nosniff`, `DENY` framing, `no-referrer`, `no-store` and a CSP.

## Known limits

- **Third-party parsers:** c2pa-rs, Pillow and ffmpeg parse the raw media. Keep them updated; Dependabot proposes updates weekly.
- **Trust:** C2PA trust is only as good as the trust list you pass with `--trust`. Signer certificates are not checked for revocation (the SDK skips OCSP).
- **Test keys:** `provlens testsign` keys are unencrypted test identities (created `0600`). Never use them to sign real content.

Checked with: bandit, semgrep, zizmor and actionlint (CI workflow clean), pip-audit (no known vulnerabilities), the mutation fuzzer, and the regression tests in `tests/test_hostile_inputs.py`, `tests/test_interfaces.py` and `tests/test_video.py`.

## Reporting

Please open a private security advisory on the repository instead of a public issue.
