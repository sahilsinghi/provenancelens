"""Render an analysis as a self-contained HTML report (and a batch triage page)."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES = Path(__file__).parent / "templates"


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]))
    env.filters["pct"] = lambda v: f"{v * 100:.0f}%"
    return env


def chain_svg(c2pa: dict[str, Any]) -> str:
    """Manifest / ingredient graph as an inline SVG (active manifest on top)."""
    if not c2pa or not c2pa.get("present") or not c2pa.get("manifests"):
        return ""
    manifests = {m["label"]: m for m in c2pa["manifests"]}
    active = next((m for m in c2pa["manifests"] if m.get("active")), None)
    if active is None:
        return ""
    levels: list[list[tuple[str, str, str | None, str | None]]] = []  # (id, title, sub, parent id)
    seen = set()
    frontier = [(active["label"], active.get("title") or "asset", f"signed by {active.get('signer') or '?'}", None)]
    while frontier and len(levels) < 5:
        levels.append(frontier)
        nxt = []
        for node_id, _, _, _ in frontier:
            m = manifests.get(node_id)
            if not m or node_id in seen:
                continue
            seen.add(node_id)
            for k, ing in enumerate(m.get("ingredients", [])):
                child = ing.get("manifest") or f"{node_id}#ing{k}"
                sub = ing.get("relationship", "")
                if ing.get("manifest") in manifests:
                    sub += f" · signed by {manifests[ing['manifest']].get('signer') or '?'}"
                else:
                    sub += " · no credentials"
                nxt.append((child, ing.get("title") or "ingredient", sub, node_id))
        frontier = nxt[:8]
    box_w, box_h, gap_x, gap_y = 210, 46, 24, 46
    width = max(len(level) for level in levels) * (box_w + gap_x) + gap_x
    height = len(levels) * (box_h + gap_y) + gap_y
    pos: dict[str, tuple[float, float]] = {}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" '
             f'style="max-width:{width}px" role="img" aria-label="C2PA ingredient graph">']
    for depth, level in enumerate(levels):
        total = len(level) * box_w + (len(level) - 1) * gap_x
        x0 = (width - total) / 2
        for i, (node_id, title, sub, parent) in enumerate(level):
            x, y = x0 + i * (box_w + gap_x), gap_y / 2 + depth * (box_h + gap_y)
            pos[node_id] = (x, y)
            if parent in pos:
                px, py = pos[parent]
                parts.append(f'<line x1="{px + box_w / 2}" y1="{py + box_h}" x2="{x + box_w / 2}" y2="{y}" '
                             f'stroke="var(--muted)" stroke-width="1.5"/>')
            fill = "var(--accent-bg)" if depth == 0 else "var(--panel)"
            parts.append(f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="8" fill="{fill}" stroke="var(--line)"/>')
            parts.append(f'<text x="{x + 10}" y="{y + 19}" font-size="12" font-weight="600" fill="var(--ink)">{html.escape(str(title)[:30])}</text>')
            parts.append(f'<text x="{x + 10}" y="{y + 35}" font-size="10.5" fill="var(--muted)">{html.escape(str(sub)[:36])}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def render_html(result: dict[str, Any]) -> str:
    return _env().get_template("report.html.j2").render(r=result, chain=chain_svg(result.get("c2pa") or {}))


def render_batch(rows: list[dict[str, Any]]) -> str:
    return _env().get_template("batch.html.j2").render(rows=rows)
