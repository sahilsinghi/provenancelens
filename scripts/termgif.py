#!/usr/bin/env python3
"""Render a scripted terminal session as an animated GIF (needs Pillow).

Input is a JSON list of steps captured from real command runs:

    [{"cmd": "provlens analyze photo.jpg", "out": "...", "hold": 2.0}, {"say": "# now tamper"}]

    python scripts/termgif.py session.json docs/demo.gif
"""

from __future__ import annotations

import json
import re
import sys
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1180, 700
PAD_X, PAD_Y, TITLE = 18, 14, 30
BG, FG, DIM = (22, 24, 29), (220, 223, 228), (128, 134, 145)
PROMPT, GREEN, RED, YELLOW, CYAN = (120, 200, 255), (98, 209, 129), (255, 107, 107), (240, 196, 92), (110, 220, 220)
FONT_CANDIDATES = ["/System/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/SFNSMono.ttf",
                   "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]


def font(size: int):
    for path in FONT_CANDIDATES:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


F = font(15)
LINE_H = 20
COLS = (W - 2 * PAD_X) // 9
ROWS = (H - TITLE - 2 * PAD_Y) // LINE_H
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def color_for(line: str) -> tuple[int, int, int]:
    s = line.strip()
    if s.startswith("$ "):
        return PROMPT
    if s.startswith("#"):
        return CYAN
    upper = s.upper()
    if "INVALID" in upper or "EDITING    : STRONG" in upper or "EDITING    : MODERATE" in upper:
        return RED
    if "(TRUSTED)" in upper or "EDITING    : NONE" in upper:
        return GREEN
    if "EDITING    : WEAK" in upper or "GENERATION : AI" in upper:
        return YELLOW
    if "[FAIL]" in upper or "RESULT: FAIL" in upper or "BLOCK" in upper or "MERGE BLOCKED" in upper or s.startswith("FAIL"):
        return RED
    if "[PASS]" in upper or "RESULT: PASS" in upper or "READY TO MERGE" in upper or s.startswith("PASS"):
        return GREEN
    if "[WARN]" in upper or "WARN" in upper[:6]:
        return YELLOW
    return FG


def wrap(text: str) -> list[str]:
    out = []
    for raw in ANSI.sub("", text).splitlines():
        out.extend(textwrap.wrap(raw, COLS, replace_whitespace=False, drop_whitespace=False) or [""])
    return out


def draw(lines: list[str], cursor: bool, title: str) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, TITLE], fill=(40, 43, 51))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 20, 9, 26 + i * 20, 21], fill=c)
    d.text((W // 2, 15), title, fill=DIM, font=font(13), anchor="mm")
    visible = lines[-ROWS:]
    y = TITLE + PAD_Y
    for line in visible:
        d.text((PAD_X, y), line, fill=color_for(line), font=F)
        y += LINE_H
    if cursor and visible:
        x = PAD_X + d.textlength(visible[-1], font=F)
        d.rectangle([x + 2, y - LINE_H + 3, x + 10, y - 3], fill=FG)
    return img


def render(steps: list[dict], out: Path, title: str) -> None:
    frames: list[Image.Image] = []
    durations: list[int] = []
    lines: list[str] = []

    def snap(ms: int, cursor: bool = False) -> None:
        frames.append(draw(lines, cursor, title))
        durations.append(ms)

    for step in steps:
        if "say" in step:
            lines.extend(wrap(step["say"]))
            snap(int(step.get("hold", 1.2) * 1000))
            continue
        cmd = "$ " + step["cmd"]
        start = len(lines)
        for i in range(2, len(cmd) + 1, 3):
            lines[start:] = wrap(cmd[:i])
            snap(35, cursor=True)
        lines[start:] = wrap(cmd)
        snap(250, cursor=True)
        out_lines = wrap(step.get("out", ""))
        chunk = max(1, len(out_lines) // 6)
        for i in range(0, len(out_lines), chunk):
            lines.extend(out_lines[i:i + chunk])
            snap(90)
        snap(int(step.get("hold", 1.8) * 1000))
    snap(4000)
    palette = frames[0].convert("P", palette=Image.ADAPTIVE, colors=32)
    converted = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    converted[0].save(out, save_all=True, append_images=converted[1:], duration=durations, loop=0, optimize=True,
                      disposal=1)


if __name__ == "__main__":
    steps = json.loads(Path(sys.argv[1]).read_text())
    render(steps, Path(sys.argv[2]), sys.argv[3] if len(sys.argv) > 3 else "demo")
    print(f"wrote {sys.argv[2]} ({Path(sys.argv[2]).stat().st_size / 1e6:.1f} MB)")
