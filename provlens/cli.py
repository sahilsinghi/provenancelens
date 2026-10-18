"""provlens command line.

    provlens analyze photo.jpg --html report.html --json report.json
    provlens analyze photo.jpg --card card.png --sign-with ./test-identity
    provlens triage ./inbox --out ./triage
    provlens qdb list | add phone.jpg --source "Pixel 9 camera" | build
    provlens evaluate --fit
    provlens datasets fetch
    provlens testsign init ./test-identity
    provlens testsign sign in.jpg out.jpg --id ./test-identity --action c2pa.cropped
    provlens serve --port 8000
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from provlens import __version__

ROOT = Path.cwd()
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".gif", ".bmp", ".heic", ".avif", ".jfif",
                  ".mp4", ".m4v", ".mov"}
EXIT_OK, EXIT_EVIDENCE, EXIT_ERROR = 0, 1, 2


def _print_summary(r: dict[str, Any], verbose: bool = False) -> None:
    if r.get("error"):
        print(f"{r['file']['name']}: {r['error']}")
        return
    v = r["verdict"]
    width = 100
    print(f"\n{r['file']['name']}  ({r['format']}, {r['file']['size']:,} bytes, sha256 {r['file']['sha256'][:16]}…)")
    if r.get("extension_mismatch"):
        print(f"  ! {r['extension_mismatch']}")
    print(textwrap.fill(v["headline"], width, initial_indent="  ", subsequent_indent="  "))
    print()
    print(textwrap.fill(v["provenance"], width, initial_indent="  provenance : ", subsequent_indent=" " * 15))
    print(f"  editing    : {v['editing_level']} (score {v['editing_score']:.2f})")
    print(f"  generation : {v['generation']}")
    print("\n  signal                                   supports      contribution")
    for s in v["signals"]:
        if not verbose and s["supports"] in ("neutral", "not_applicable"):
            continue
        weighted = s["supports"] in ("edited", "generated", "authentic", "declared")
        contrib = f"{s['strength']:.2f} x {s['weight']:.2f} = {s['contribution']:.2f}" if weighted else "-"
        print(f"  {s['title'][:40]:<40} {s['supports']:<13} {contrib}")
    hidden = sum(1 for s in v["signals"] if s["supports"] in ("neutral", "not_applicable"))
    if hidden and not verbose:
        print(f"  (+{hidden} neutral / not-applicable signals; --verbose shows them)")
    print(f"\n  analysed in {r['seconds']}s")


def cmd_analyze(a: argparse.Namespace) -> int:
    from provlens import card, report
    from provlens.analyze import analyse

    status = EXIT_OK
    for path in a.files:
        r = analyse(Path(path), a.trust or None, maps=not a.no_maps or bool(a.html or a.card))
        if a.json:
            out = _out_for(a.json, path, ".json", len(a.files))
            out.write_text(json.dumps(r, indent=1, default=str) if a.embed_images else
                           json.dumps(_strip_images(r), indent=1, default=str))
            print(f"wrote {out}")
        if a.html and not r.get("error"):
            out = _out_for(a.html, path, ".html", len(a.files))
            out.write_text(report.render_html(r), encoding="utf-8")
            print(f"wrote {out}")
        if a.card and not r.get("error"):
            out = _out_for(a.card, path, ".card.png", len(a.files))
            card.write(r, out, analysed=Path(path), identity_dir=Path(a.sign_with) if a.sign_with else None)
            print(f"wrote {out}" + (" (C2PA-signed)" if a.sign_with else ""))
        if not a.quiet:
            _print_summary(r, a.verbose)
        if r.get("error"):
            status = max(status, EXIT_ERROR)
        elif r["verdict"]["editing_level"] in ("moderate", "strong") or (r.get("c2pa") or {}).get("state") == "Invalid":
            status = max(status, EXIT_EVIDENCE)
    return status


def _out_for(target: str, src: str, suffix: str, n: int) -> Path:
    t = Path(target)
    if n > 1 or t.is_dir():
        t.mkdir(parents=True, exist_ok=True)
        return t / (Path(src).stem + suffix)
    t.parent.mkdir(parents=True, exist_ok=True)
    return t


def _strip_images(r: dict[str, Any]) -> dict[str, Any]:
    r = json.loads(json.dumps(r, default=str))
    r.get("image", {}).pop("thumbnail_jpeg_b64", None)
    for m in (r.get("pixel") or {}).values():
        m.pop("heatmap_png_b64", None)
    return r


def _triage_one(args: tuple[str, str, list[str]]) -> dict[str, Any]:
    from provlens import report
    from provlens.analyze import analyse

    path, out_dir, trust = args
    p = Path(path)
    try:
        r = analyse(p, [Path(t) for t in trust] or None)
    except Exception as exc:  # noqa: BLE001 - one bad file must not stop a batch
        return {"name": p.name, "format": "?", "level": "error", "score": -1, "generated": False,
                "c2pa": "", "headline": f"analysis failed: {exc}", "thumb": None, "report": ""}
    stem = f"{p.stem}-{r['file']['sha256'][:8]}"
    if r.get("error"):
        return {"name": p.name, "format": r["format"], "level": "skipped", "score": -1, "generated": False,
                "c2pa": "", "headline": r["error"], "thumb": None, "report": ""}
    (Path(out_dir) / "reports" / f"{stem}.html").write_text(report.render_html(r), encoding="utf-8")
    (Path(out_dir) / "reports" / f"{stem}.json").write_text(json.dumps(_strip_images(r), indent=1))
    v = r["verdict"]
    return {"name": p.name, "format": r["format"], "level": v["editing_level"], "score": v["editing_score"],
            "generated": v["generation_score"] >= 0.5, "c2pa": (r.get("c2pa") or {}).get("state", ""),
            "headline": v["headline"], "thumb": (r.get("image") or {}).get("thumbnail_jpeg_b64"),
            "report": f"reports/{stem}.html"}


def cmd_triage(a: argparse.Namespace) -> int:
    from provlens import report

    src = Path(a.folder)
    files = sorted(p for p in (src.rglob("*") if a.recursive else src.iterdir())
                   if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES)
    if not files:
        print(f"no images under {src}", file=sys.stderr)
        return EXIT_ERROR
    out = Path(a.out)
    (out / "reports").mkdir(parents=True, exist_ok=True)
    jobs = [(str(p), str(out), list(a.trust or [])) for p in files]
    if a.jobs > 1:
        with ProcessPoolExecutor(a.jobs) as ex:
            rows = list(ex.map(_triage_one, jobs))
    else:
        rows = []
        for i, j in enumerate(jobs, 1):
            rows.append(_triage_one(j))
            print(f"  [{i}/{len(jobs)}] {rows[-1]['name']}: {rows[-1]['level']}", file=sys.stderr)
    rows.sort(key=lambda x: (-int(x["generated"]), -x["score"], x["name"]))
    (out / "index.html").write_text(report.render_batch(rows), encoding="utf-8")
    (out / "triage.json").write_text(json.dumps([{k: v for k, v in x.items() if k != "thumb"} for x in rows], indent=1))
    print(f"{len(rows)} files -> {out / 'index.html'}")
    for x in rows[: a.top]:
        print(f"  {x['level']:<9} {x['score']:>5.2f}  {x['name']}")
    return EXIT_OK


def cmd_qdb(a: argparse.Namespace) -> int:
    from provlens import qtables

    if a.qdb_cmd == "build":
        db = qtables.build_db()
        fams: dict[str, int] = {}
        for e in db:
            fams[e["family"]] = fams.get(e["family"], 0) + 1
        print(f"wrote {qtables.DB_PATH} with {len(db)} entries: {fams}")
    elif a.qdb_cmd == "add":
        e = qtables.add_sample(Path(a.image), a.source, a.family, a.quality)
        print(f"added {e['source']} ({e['family']}, {e['quality']})")
    elif a.qdb_cmd == "list":
        fams: dict[str, list[str]] = {}
        for e in qtables.load_db():
            fams.setdefault(f"{e['family']}: {e['source']}", []).append(e["quality"])
        for k, qs in fams.items():
            print(f"{k}  [{len(qs)}] {', '.join(qs[:6])}{' …' if len(qs) > 6 else ''}")
    elif a.qdb_cmd == "match":
        from provlens import jpeg

        info = jpeg.parse(Path(a.image).read_bytes())
        print(json.dumps(qtables.describe(info.luma, info.chroma), indent=1))
    return EXIT_OK


def cmd_evaluate(a: argparse.Namespace) -> int:
    from provlens import evaluate

    out = Path(a.out)
    items = evaluate.generate(out, per_source=a.per_source, seed=a.seed)
    print(f"generated {len(items)} labelled images in {out}", file=sys.stderr)
    rep = evaluate.evaluate(items, fit_models=a.fit)
    rep["items"] = dict(rep["items"])
    (out / "report.json").write_text(json.dumps(rep, indent=1, default=str))
    d = rep["djpeg"]
    print(f"double-JPEG  : confusion {d['confusion']}  rates {d['rates']}")
    print(f"               flagged share by kind {d['flagged_share_by_kind']}")
    for name, m in rep["pixel"].items():
        print(f"pixel {name:<6} : {json.dumps({k: v for k, v in m.items() if k != 'per_kind'})}")
    vv = rep["verdicts"]
    print("verdicts     :")
    for kind, row in vv["matrix"].items():
        print(f"   {kind:<12} {row}")
    print(f"   AI declared recognised {vv['ai_declared_recognised']}, stripped shown as limited {vv['stripped_limited_signal']}")
    print(f"   splice vs benign (moderate+): {vv['binary']}  {vv['binary_confusion']}")
    if a.fit:
        print("models written to provlens/data/ (djpeg_model.json, pixel_thresholds.json)")
    print(f"report: {out / 'report.json'}")
    return EXIT_OK


def cmd_datasets(a: argparse.Namespace) -> int:
    from provlens import datasets

    paths = datasets.fetch(Path(a.root))
    print(f"{len(paths)} files verified in {datasets.cache_dir(Path(a.root))} "
          f"({datasets.REPO}@{datasets.COMMIT[:12]}, {datasets.LICENSE})")
    return EXIT_OK


def cmd_testsign(a: argparse.Namespace) -> int:
    from provlens import testsign

    if a.ts_cmd == "init":
        ident = testsign.make_identity(Path(a.folder), a.name)
        print(f"test identity in {a.folder}: trust anchor {ident.root_pem.name}, chain {ident.chain_pem.name}, "
              f"key {ident.key_pem.name} (unencrypted, TEST ONLY)")
    else:
        ident = testsign.load_identity(Path(a.id))
        actions = [{"action": x} for x in a.action] if a.action else None
        out = testsign.sign(Path(a.source), Path(a.dest), ident, title=a.title, actions=actions,
                            parent=Path(a.parent) if a.parent else None)
        print(f"signed {out}")
    return EXIT_OK


def cmd_serve(a: argparse.Namespace) -> int:
    import uvicorn

    from provlens.server import create_app

    app = create_app(trust_anchors=[Path(t) for t in a.trust or []], max_bytes=a.max_mb * 1024 * 1024)
    if a.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: listening on {a.host}; anyone who can reach it can upload files", file=sys.stderr)
    uvicorn.run(app, host=a.host, port=a.port, log_level="info")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="provlens", description="Explainable media-authenticity verifier: "
                                "C2PA validation, metadata consistency and compression forensics, with every signal explained.")
    p.add_argument("--version", action="version", version=f"provlens {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser("analyze", aliases=["analyse"], help="analyse one or more images")
    an.add_argument("files", nargs="+")
    an.add_argument("--trust", action="append", metavar="PEM", help="trust anchor(s) for C2PA signers (repeatable)")
    an.add_argument("--html", metavar="PATH", help="write an HTML report (a folder when several files are given)")
    an.add_argument("--json", metavar="PATH", help="write the full analysis as JSON")
    an.add_argument("--embed-images", action="store_true", help="keep thumbnail and heatmaps (base64) in the JSON")
    an.add_argument("--card", metavar="PATH", help="write a one-image summary card (PNG)")
    an.add_argument("--sign-with", metavar="DIR", help="C2PA-sign the card with the test identity in DIR")
    an.add_argument("--no-maps", action="store_true", help="skip the pixel maps (faster)")
    an.add_argument("-q", "--quiet", action="store_true")
    an.add_argument("-v", "--verbose", action="store_true", help="also list neutral signals")
    an.set_defaults(func=cmd_analyze)

    tr = sub.add_parser("triage", aliases=["batch"], help="analyse a folder and rank it by editing evidence")
    tr.add_argument("folder")
    tr.add_argument("--out", default="triage")
    tr.add_argument("--trust", action="append", metavar="PEM")
    tr.add_argument("--recursive", "-r", action="store_true")
    tr.add_argument("--jobs", "-j", type=int, default=1)
    tr.add_argument("--top", type=int, default=10, help="how many rows to print")
    tr.set_defaults(func=cmd_triage)

    q = sub.add_parser("qdb", help="quantisation-table fingerprint database")
    qs = q.add_subparsers(dest="qdb_cmd", required=True)
    qs.add_parser("build", help="regenerate from the encoders on this machine (Pillow, sips, ffmpeg)")
    qa = qs.add_parser("add", help="record the tables of a reference JPEG")
    qa.add_argument("image")
    qa.add_argument("--source", required=True, help='e.g. "Pixel 9 camera" or "WhatsApp re-upload"')
    qa.add_argument("--family", default="user")
    qa.add_argument("--quality", default="")
    qs.add_parser("list")
    qm = qs.add_parser("match", help="show the closest encoders for a JPEG")
    qm.add_argument("image")
    q.set_defaults(func=cmd_qdb)

    ev = sub.add_parser("evaluate", help="generate the labelled set and measure every detector")
    ev.add_argument("--out", default=".cache/eval")
    ev.add_argument("--per-source", type=int, default=6)
    ev.add_argument("--seed", type=int, default=2026)
    ev.add_argument("--fit", action="store_true", help="refit the double-JPEG model and pixel thresholds")
    ev.set_defaults(func=cmd_evaluate)

    ds = sub.add_parser("datasets", help="public C2PA conformance samples")
    dss = ds.add_subparsers(dest="ds_cmd", required=True)
    df = dss.add_parser("fetch", help="download the pinned samples into .cache/ and verify their hashes")
    df.add_argument("--root", default=".")
    ds.set_defaults(func=cmd_datasets)

    ts = sub.add_parser("testsign", help="throwaway C2PA signing identity (tests and demos only)")
    tss = ts.add_subparsers(dest="ts_cmd", required=True)
    ti = tss.add_parser("init")
    ti.add_argument("folder")
    ti.add_argument("--name", default="ProvenanceLens Test Signer")
    tsg = tss.add_parser("sign")
    tsg.add_argument("source")
    tsg.add_argument("dest")
    tsg.add_argument("--id", required=True, metavar="DIR")
    tsg.add_argument("--title")
    tsg.add_argument("--action", action="append", help="C2PA action to declare, e.g. c2pa.cropped (repeatable)")
    tsg.add_argument("--parent", help="earlier version of the asset, recorded as the parentOf ingredient")
    ts.set_defaults(func=cmd_testsign)

    sv = sub.add_parser("serve", help="local web page: drop an image, get the report")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--trust", action="append", metavar="PEM")
    sv.add_argument("--max-mb", type=int, default=40)
    sv.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"provlens: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
