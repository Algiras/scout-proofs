"""Render the .excalidraw scenes in this directory to SVG and PNG using styles.json.

Usage: python3 render.py [scene-dir] [out-dir]
PNG output needs `rsvg-convert` (librsvg) on PATH.
"""
import json
import math
import shutil
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
STYLE = json.loads((HERE / "styles.json").read_text())


def dash_attrs(width, dashed):
    if not dashed:
        return width, ""
    gap = STYLE["dash"]["dash"] + width
    return width + STYLE["dash"]["extraWidth"], f' stroke-dasharray="{STYLE["dash"]["dash"]} {gap:g}"'


def absolute_points(el):
    return [(el["x"] + px, el["y"] + py) for px, py in el["points"]]


def polyline(pts, color, width, dashed):
    w, dash = dash_attrs(width, dashed)
    d = "M" + " L".join(f"{x:.2f} {y:.2f}" for x, y in pts)
    return f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{w:g}" stroke-linecap="round" stroke-linejoin="round"{dash}/>'


def arrowhead(tail, tip, color, width):
    seg = math.dist(tail, tip)
    if seg == 0:
        return ""
    length = min(STYLE["arrow"]["headLength"], seg / 2)
    back = math.atan2(tail[1] - tip[1], tail[0] - tip[0])
    out = []
    for sign in (1, -1):
        a = back + sign * math.radians(STYLE["arrow"]["headAngleDeg"])
        end = (tip[0] + length * math.cos(a), tip[1] + length * math.sin(a))
        out.append(polyline([end, tip], color, width, False))
    return "".join(out)


def render_rect(el):
    x, y, w, h = el["x"], el["y"], el["width"], el["height"]
    dashed = el.get("strokeStyle") == "dashed"
    r = 0.0
    if el.get("roundness"):
        r = min(min(w, h) * STYLE["box"]["cornerRatio"], STYLE["box"]["maxCornerRadius"])
    sw, dash = dash_attrs(STYLE["box"]["strokeWidth"], dashed)
    fill = "none" if dashed else STYLE["colors"]["boxFill"]
    return (f'<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="{r:g}" fill="{fill}" '
            f'stroke="{STYLE["colors"]["boxStroke"]}" stroke-width="{sw:g}"{dash}/>')


def render_text(el):
    fs = el["fontSize"]
    lh = fs * STYLE["font"]["lineHeight"]
    anchor, x = "start", el["x"]
    if el.get("textAlign") == "center":
        anchor, x = "middle", el["x"] + el["width"] / 2
    lines = el["text"].split("\n")
    spans = "".join(
        f'<text x="{x:.2f}" y="{el["y"] + fs * STYLE["font"]["baseline"] + i * lh:.2f}" '
        f'text-anchor="{anchor}">{escape(line)}</text>'
        for i, line in enumerate(lines)
    )
    return (f'<g font-family="{STYLE["font"]["family"]}" font-size="{fs:g}px" '
            f'fill="{STYLE["colors"]["text"]}" style="white-space: pre">{spans}</g>')


def render_arrow(el):
    pts = absolute_points(el)
    color = STYLE["colors"]["arrow"]
    width = STYLE["arrow"]["strokeWidth"]
    out = [polyline(pts, color, width, el.get("strokeStyle") == "dashed")]
    if el.get("endArrowhead"):
        out.append(arrowhead(pts[-2], pts[-1], color, width))
    if el.get("startArrowhead"):
        out.append(arrowhead(pts[1], pts[0], color, width))
    return "".join(out)


def render_line(el):
    return polyline(absolute_points(el), STYLE["colors"]["lifeline"], el.get("strokeWidth", 1),
                    el.get("strokeStyle") == "dashed")


RENDER = {"rectangle": render_rect, "text": render_text, "arrow": render_arrow, "line": render_line}


def bounds(el):
    if el["type"] in ("arrow", "line"):
        xs, ys = zip(*absolute_points(el))
        return min(xs), min(ys), max(xs), max(ys)
    return el["x"], el["y"], el["x"] + el["width"], el["y"] + el["height"]


def to_svg(scene):
    els = [e for e in scene["elements"] if not e.get("isDeleted") and e["type"] in RENDER]
    boxes = [bounds(e) for e in els]
    pad = STYLE["export"]["padding"]
    x0 = min(b[0] for b in boxes) - pad
    y0 = min(b[1] for b in boxes) - pad
    w = max(b[2] for b in boxes) + pad - x0
    h = max(b[3] for b in boxes) + pad - y0
    scale = STYLE["export"]["scale"]
    body = "\n".join(RENDER[e["type"]](e) for e in els)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x0:g} {y0:g} {w:g} {h:g}" '
            f'width="{w * scale:g}" height="{h * scale:g}">\n'
            f'<rect x="{x0:g}" y="{y0:g}" width="{w:g}" height="{h:g}" fill="{STYLE["colors"]["background"]}"/>\n'
            f"{body}\n</svg>\n")


def main():
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else src
    out.mkdir(parents=True, exist_ok=True)
    rsvg = shutil.which("rsvg-convert")
    for scene_path in sorted(src.glob("*.excalidraw")):
        svg_path = out / f"{scene_path.stem}.svg"
        svg_path.write_text(to_svg(json.loads(scene_path.read_text())))
        if rsvg:
            subprocess.run([rsvg, "-b", STYLE["colors"]["background"], str(svg_path), "-o",
                            str(out / f"{scene_path.stem}.png")], check=True)
        print(svg_path.name, "+ png" if rsvg else "(no rsvg-convert: png skipped)")


if __name__ == "__main__":
    main()
