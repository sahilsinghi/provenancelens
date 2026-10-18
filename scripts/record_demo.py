#!/usr/bin/env python3
"""Run the README demo for real and record it as a GIF.

    python scripts/record_demo.py docs/demo.gif      (needs scikit-image for the input photos)

Every command shown in the GIF is executed in a scratch directory and its real
output is captured; nothing is typed in by hand.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(sys.executable).parent

MAKE_INPUTS = r'''
import io
from pathlib import Path
from PIL import Image
from skimage import data
from provlens import testsign

def jpg(im, q):
    b = io.BytesIO(); im.save(b, "JPEG", quality=q); return b.getvalue()
def op(b):
    return Image.open(io.BytesIO(b)).convert("RGB")

ident = testsign.load_identity(Path("id"))
Path("raw.jpg").write_bytes(jpg(Image.fromarray(data.astronaut()), 90))
testsign.sign(Path("raw.jpg"), Path("signed.jpg"), ident, title="astronaut.jpg")
b = bytearray(Path("signed.jpg").read_bytes()); b[len(b) - 4000] ^= 1
Path("tampered.jpg").write_bytes(bytes(b))
bg = op(jpg(Image.fromarray(data.astronaut()), 70))
bg.paste(op(jpg(Image.fromarray(data.chelsea()).crop((150, 40, 330, 220)), 45)), (300, 60))
Path("inbox").mkdir()
Path("inbox/edited.jpg").write_bytes(jpg(bg, 90))
Path("inbox/holiday.jpg").write_bytes(jpg(Image.fromarray(data.coffee()), 85))
Path("inbox/reupload.jpg").write_bytes(jpg(op(jpg(Image.fromarray(data.rocket()), 92)).resize((341, 512)), 75))
Image.fromarray(data.chelsea()).save("inbox/screenshot.png")
Path("raw.jpg").unlink()
'''


def main() -> int:
    out_gif = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "demo.gif"
    work = Path(tempfile.mkdtemp(prefix="provlens-demo-"))
    env = {**os.environ, "NO_COLOR": "1", "COLUMNS": "110", "PATH": f"{BIN}:{os.environ['PATH']}"}

    def run(cmd: str) -> str:
        p = subprocess.run(cmd, shell=True, cwd=work, env=env, capture_output=True, text=True)
        return (p.stdout + p.stderr).rstrip()

    run("provlens testsign init id --name 'Demo Camera'")
    (work / "make_inputs.py").write_text(MAKE_INPUTS)
    print(run(f"{shlex.quote(sys.executable)} make_inputs.py"))

    steps: list[dict] = [{"say": "# ProvenanceLens: what can this image's history actually show?", "hold": 1.5}]

    def step(cmd: str, hold: float = 2.5, drop: tuple[str, ...] = ("analysed in", "wrote ", "  [")) -> None:
        lines = [ln for ln in run(cmd).splitlines() if not any(d in ln for d in drop)]
        steps.append({"cmd": cmd, "out": "\n".join(lines).strip("\n"), "hold": hold})

    step("provlens analyze signed.jpg --trust id/test-root.pem", hold=3.0)
    steps.append({"say": "# flip one bit of the compressed pixels after signing", "hold": 1.5})
    step("provlens analyze tampered.jpg --trust id/test-root.pem", hold=3.5)
    steps.append({"say": "# no credentials at all: a pasted patch, a holiday photo, a re-upload, a PNG", "hold": 1.5})
    step("provlens triage inbox --out triage", hold=4.0)
    step("provlens analyze inbox/edited.jpg --html edited.html", hold=4.5)

    session = work / "session.json"
    session.write_text(json.dumps(steps, indent=1))
    subprocess.run([sys.executable, str(ROOT / "scripts" / "termgif.py"), str(session), str(out_gif),
                    "provenancelens demo"], check=True)
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
