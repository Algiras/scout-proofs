#!/usr/bin/env python3
"""Generate fig7.excalidraw: example Kubernetes topology of the Helm chart."""
import json

els = []
def base(kind, x, y, w, h, **kw):
    e = {"id": f"{kind}{len(els)}", "type": kind, "x": x, "y": y, "width": w, "height": h, "angle": 0,
         "strokeColor": "#495057", "backgroundColor": "transparent", "fillStyle": "solid", "strokeWidth": 1.5,
         "strokeStyle": "solid", "roughness": 0, "opacity": 100, "groupIds": [], "frameId": None,
         "roundness": None, "isDeleted": False, "boundElements": [], "link": None, "locked": False}
    e.update(kw)
    els.append(e)
    return e

def text(x, y, w, s, size=16, align="center"):
    n = s.count("\n") + 1
    base("text", x, y, w, n * size * 1.15, strokeColor="#1e1e1e", strokeWidth=1, text=s, originalText=s,
         fontSize=size, fontFamily=2, textAlign=align, verticalAlign="top", containerId=None,
         lineHeight=1.15, autoResize=True)

def box(x, y, w, h, label, dashed=False):
    base("rectangle", x, y, w, h, roundness={"type": 3}, strokeStyle="dashed" if dashed else "solid",
         backgroundColor="transparent" if dashed else "#f1f3f5")
    if label:
        n = label.count("\n") + 1
        text(x, y + (h - n * 16 * 1.15) / 2, w, label)

def arrow(x, y, pts, dashed=False):
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    base("arrow", x, y, max(xs) - min(xs), max(ys) - min(ys), strokeColor="#343a40", strokeWidth=2,
         strokeStyle="dashed" if dashed else "solid", points=[[0, 0]] + [list(p) for p in pts],
         lastCommittedPoint=None, startBinding=None, endBinding=None, startArrowhead=None,
         endArrowhead="arrow", elbowed=False)

text(330, -10, 600, "EXAMPLE KUBERNETES TOPOLOGY OF THE HELM CHART", size=20)
box(220, 40, 920, 520, "", dashed=True)
text(240, 525, 300, "Namespace (one Helm release)", align="left")

box(0, 60, 190, 80, "Principal\nBrowser")
box(250, 130, 230, 120, "Runner Job\nscout-run and workload\nKeys in memory only")
box(680, 130, 240, 120, "Broker Deployment\nscoutd, one replica\nbehind a Service")
box(950, 105, 160, 80, "Secret\nClient secret\nCommitment key")
box(950, 205, 160, 80, "Volume\nSealed tokens\nCommitments")
box(680, 400, 240, 120, "Provider\nMock OAuth server here,\nexternal in practice")

arrow(190, 85, [(610, 0), (610, 45)])
text(300, 62, 300, "Consent in the browser", align="left")
arrow(480, 165, [(200, 0)])
text(480, 142, 200, "Bind, signed requests")
arrow(680, 220, [(-200, 0)], dashed=True)
text(480, 226, 200, "Sealed grants")
arrow(920, 150, [(30, 0)])
arrow(920, 235, [(30, 0)])
arrow(770, 250, [(0, 150)])
arrow(830, 400, [(0, -150)], dashed=True)
text(845, 300, 280, "Exchange, refresh and revoke\nwith the client secret", align="left")
text(845, 350, 280, "NetworkPolicy: only the broker\nreaches the token endpoint", size=14, align="left")
arrow(365, 250, [(0, 215), (315, 215)])
text(380, 438, 290, "API calls with the access token", align="left")

json.dump({"type": "excalidraw", "version": 2, "source": "gen_topology.py", "elements": els,
           "appState": {"viewBackgroundColor": "#ffffff", "gridSize": None}, "files": {}},
          open("fig7.excalidraw", "w"), indent=1)
