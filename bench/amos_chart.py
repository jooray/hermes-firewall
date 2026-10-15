"""Chart for the Amos 1 section of the blog post: text AUC per detector, and image-carrier AUC with OCR vs picture.
    uv run python amos_chart.py OUT.png"""
import json
import sys

import matplotlib.pyplot as plt

INK, INK2, GRID, PAPER = "#16212b", "#4a5661", "#e4e8ec", "#ffffff"
a = json.load(open("results_local_sysone.json"))["models"]
im = json.load(open("results_d1_images.json"))
text = [("Jev (cloud)", a["Jev jev-latest (Venice)"], "#2a78d6"), ("d3 27B 4-bit", a["d3 27B MLX 4-bit"], "#7a1f1f"),
        ("Amos medium 9B", a["Amos 1 medium 9B MLX"], "#0f7b9e"), ("Amos small 2B", a["Amos 1 small 2B MLX"], "#5bb3cf"),
        ("Amos mini 0.5B", a["Amos 1 mini 0.5B (torch CPU)"], "#a9b4bd")]
pics = [("RSI-Jev 4B", "RSI-Jev v6.1-VL 4B"), ("Amos medium 9B", "Amos 1 medium 9B"), ("Amos small 2B", "Amos 1 small 2B"),
        ("Amos mini 0.5B", "Amos 1 mini 0.5B")]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "text.color": INK, "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK})
fig, (l, r) = plt.subplots(1, 2, figsize=(11, 4.6), dpi=200, gridspec_kw={"width_ratios": [1, 1.1]})
for ax in (l, r):
    ax.set_facecolor(PAPER)
    ax.grid(axis="x", color=GRID)
    ax.set_axisbelow(True)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
ys = range(len(text))[::-1]
for y, (n, m, c) in zip(ys, text):
    v = m["auc"]["Overall"]
    l.barh(y, v, color=c, height=0.62)
    l.text(v + 0.006, y, f"{v:.3f}", va="center", fontsize=10)
l.set_yticks(list(ys), [t[0] for t in text])
l.set_xlim(0.5, 1.03)
l.set_title("Test AUC, all 718 items (text)", loc="left", fontsize=12)
ys = range(len(pics))[::-1]
for y, (n, k) in zip(ys, pics):
    o, p = im[f"{k} | OCR text | all image items"]["auc"], im[f"{k} | picture | all image items"]["auc"]
    r.barh(y + 0.17, o, color="#8a94a0", height=0.32, label="OCR text" if y == len(pics) - 1 else None)
    r.barh(y - 0.17, p, color="#eb6834", height=0.32, label="Picture itself" if y == len(pics) - 1 else None)
    r.text(o + 0.006, y + 0.17, f"{o:.3f}", va="center", fontsize=9)
    r.text(p + 0.006, y - 0.17, f"{p:.3f}", va="center", fontsize=9)
r.set_yticks(list(ys), [p[0] for p in pics])
r.set_xlim(0.5, 1.03)
r.set_title("Image carriers (102 items): OCR vs picture", loc="left", fontsize=12)
r.legend(loc="lower right", frameon=False, fontsize=9)
fig.tight_layout()
fig.savefig(sys.argv[1], facecolor=PAPER)
