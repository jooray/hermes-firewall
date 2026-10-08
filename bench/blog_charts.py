"""The two blog charts, computed from the saved scores and the shipped policies.

Test items: the whole test split minus items whose extracted text also occurs in dev (identical
detector input, see evaluate.dev_duplicates) and minus items whose extracted text changed after a
detector was scored (corpus/test.changed_v5.json), so every detector is compared on the same text.
Verdicts use each backend's shipped policy file; local System One models (Ollama, MLX or the d1 shim, scored by
score_ollama.py) have no shipped policy and get Jev's policy with thresholds refitted on their own
dev scores (block @1%, warn @5% dev FPR, as for policy-jev.json). A verdict is block or pass;
"flagged" (warn threshold, hidden content) is a log entry, not something the model sees. Writes results_blog.json and, with a
directory argument, auc-by-slice.png and verdicts.png there.
"""
import json
import sys
from importlib.resources import files

from sklearn.metrics import roc_auc_score

from evaluate import HIDING_FLAGS, dev_duplicates, load, pick_threshold, scores

sys.path.insert(0, "../firewall/src")
from hermes_firewall.policy import Policy  # noqa: E402

dev, test = load("dev"), load("test")
try:  # written when the corpus was re-extracted; absent in a fresh build, where nothing is stale
    changed = set(json.load(open("corpus/test.changed_v5.json")))
except FileNotFoundError:
    changed = set()
DET = {  # label: (score tag, policy backend or None, score function for non-policy detectors)
    "Jev (cloud)": ("jev_deployed", "jev", None),
    "RSI-Jev v6.1-VL 4B": ("rsi-jev-v6.1-vl-4b", "refit", None),
    "Nimble 9B 4-bit": ("ollama_nimble-9b-q4_K_M", "refit", None),
    "Tev1 4B": ("ollama_tev1-4b", "refit", None),
    "Lux 9B MLX 4-bit": ("mlx_lux-9b-4bit", "refit", None),
    "d1-3B": ("d1-3b", "refit", None),
    "d1-omni-600M": ("d1-omni-600m", "refit", None),
    "SemIf Qwen3.5-4B 8-bit": ("semif_q8", "semif", None),
    "SemIf Qwen3.5-4B BF16": ("semif", "semif", None),
    "SemIf Qwen3.5-4B 4-bit": ("semif_q4", "semif", None),
    "Laya 421M": ("laya_en", "laya", None),
    "DeBERTa v2": ("deberta", None, lambda s: s["p"]),
    "Keyword regex": ("regex", None, lambda s: s["p"]),
}
CHART = ["Jev (cloud)", "RSI-Jev v6.1-VL 4B", "Nimble 9B 4-bit", "d1-3B", "Lux 9B MLX 4-bit", "SemIf Qwen3.5-4B 8-bit", "Laya 421M", "DeBERTa v2"]
S = {k: scores(tag, "test") for k, (tag, _, _) in DET.items()}
SD = {k: scores(tag, "dev") for k, (tag, _, _) in DET.items()}
DET = {k: v for k, v in DET.items() if S.get(k) and SD.get(k)}  # only models with both splits scored
S, SD = {k: S[k] for k in DET}, {k: SD[k] for k in DET}
ids = sorted(set(test) - dev_duplicates(dev, test) - changed)
ids = [i for i in ids if all(i in S[k] for k in DET)]


def shipped(b):
    return Policy(**json.loads(files("hermes_firewall").joinpath(f"policy-{b}.json").read_text()))


def refit(k):
    """Jev's policy (questions, aggregation) with thresholds fitted on this model's dev scores."""
    pol = shipped("jev")
    v = [(pol.score(SD[k][i]["text"]), dev[i]["label"]) for i in dev if i in SD[k]]
    pos, neg = [a for a, l in v if l], [a for a, l in v if not l]
    return Policy(**(pol.describe() | {"block": float(pick_threshold(pos, neg, 0.01)),
                                       "warn": float(pick_threshold(pos, neg, 0.05))}))


POL = {k: refit(k) if b == "refit" else shipped(b) for k, (_, b, _) in DET.items() if b}


def score_fn(k):
    _, b, f = DET[k]
    return f if f else POL[k].score


SLICES = [
    ("Planted instruction in email (BIPIA)", lambda r: r["source"] == "bipia_email"),
    ("Direct injections (deepset)", lambda r: r["source"] == "deepset"),
    ("Gandalf vs all benign", lambda r: r["source"] == "gandalf" or r["label"] == 0),
    ("Markup carriers (attributes, scripts)", lambda r: r["source"] == "carrier" and r["category"].startswith("attr_")),
    ("All hidden-text carriers", lambda r: r["source"] == "carrier" and r["kind"] == "text"),
    ("Image carriers", lambda r: r["source"] == "carrier" and r["kind"] == "image"),
    ("All attacks vs Nostr posts", lambda r: r["label"] == 1 or r["source"] == "nostr"),
    ("Overall", lambda r: True),
]
out = {"n_test": len(ids), "attacks": sum(test[i]["label"] for i in ids), "auc": {}, "verdicts": {}}
for name, f in SLICES:
    sl = [i for i in ids if f(test[i])]
    out["auc"][name] = {k: roc_auc_score([test[i]["label"] for i in sl], [score_fn(k)(S[k][i]["text"]) for i in sl])
                        for k in DET}
groups = [("all attacks", lambda r: r["label"] == 1), ("planted email", lambda r: r["source"] == "bipia_email" and r["label"] == 1),
          ("benign", lambda r: r["label"] == 0)]
for k, (_, b, _) in DET.items():
    if not b:
        continue
    for g, f in groups:
        sel = [i for i in ids if f(test[i])]
        c = {"blocked": 0, "flagged": 0, "passed": 0}
        for i in sel:
            v = POL[k].decide(S[k][i]["text"], [x for x in test[i]["flags"] if x in HIDING_FLAGS])["verdict"]
            c["blocked" if v == "injection" else "flagged" if v == "suspicious" else "passed"] += 1
        out["verdicts"][f"{k} | {g}"] = {"n": len(sel), **{x: 100 * y / len(sel) for x, y in c.items()}}
out["table"] = {}
for k in DET:  # one threshold at 2% dev FPR, like bench/compare_variants.py
    d_ids = [i for i in dev if i in SD[k]]
    y = [dev[i]["label"] for i in d_ids]
    v = [score_fn(k)(SD[k][i]["text"]) for i in d_ids]
    thr = pick_threshold([a for a, l in zip(v, y) if l], [a for a, l in zip(v, y) if not l], 0.02)
    ys = [test[i]["label"] for i in ids]
    vs = [score_fn(k)(S[k][i]["text"]) for i in ids]
    out["table"][k] = {"auc": out["auc"]["Overall"][k], "planted_email_auc": out["auc"]["Planted instruction in email (BIPIA)"][k],
                       "tpr_at_dev2": sum(a >= thr for a, l in zip(vs, ys) if l) / sum(ys),
                       "fpr_at_dev2": sum(a >= thr for a, l in zip(vs, ys) if not l) / (len(ys) - sum(ys))}
json.dump(out, open("results_blog.json", "w"), indent=1)
print(json.dumps(out, indent=1))

if len(sys.argv) > 1:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    OUT = sys.argv[1].rstrip("/") + "/"
    INK, INK2, INK3, GRID, PAPER = "#16212b", "#4a5661", "#6f7a84", "#e4e8ec", "#ffffff"
    COL = {"Jev (cloud)": "#2a78d6", "RSI-Jev v6.1-VL 4B": "#0f7b9e", "Nimble 9B 4-bit": "#8a4fd0", "Lux 9B MLX 4-bit": "#c9a227", "d1-3B": "#d6457f", "SemIf Qwen3.5-4B 8-bit": "#eb6834", "Laya 421M": "#1baf7a", "DeBERTa v2": "#8a8f98"}
    LABEL = {"RSI-Jev v6.1-VL 4B": "RSI-Jev 4B (local)", "Nimble 9B 4-bit": "Nimble 4-bit (local)", "Lux 9B MLX 4-bit": "Lux 4-bit (local)", "d1-3B": "d1-3B (local)", "SemIf Qwen3.5-4B 8-bit": "SemIf 8-bit"}
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "text.color": INK, "axes.labelcolor": INK2,
                         "xtick.color": INK3, "ytick.color": INK})
    fig, ax = plt.subplots(figsize=(10, 5.6), dpi=200)
    fig.patch.set_facecolor(PAPER)
    n = len(SLICES)
    for j, (name, _) in enumerate(SLICES):
        y = n - 1 - j
        vals = [out["auc"][name][k] for k in CHART]
        ax.plot([min(vals), max(vals)], [y, y], color="#d5dbe0", lw=2, zorder=1)
        for ci, (k, v) in enumerate(zip(CHART, vals)):
            ax.scatter(v, y + 0.08 * (ci - (len(CHART) - 1) / 2), s=70, color=COL[k], edgecolor=PAPER, linewidth=1.5, zorder=3, label=LABEL.get(k, k) if j == 0 else None)
    ax.set_yticks(range(n))
    ax.set_yticklabels([s[0] for s in SLICES][::-1])
    for lab in ax.get_yticklabels():
        if lab.get_text() in ("Overall", "Planted instruction in email (BIPIA)"):
            lab.set_fontweight("bold")
    ax.axvline(0.5, color=INK3, ls=(0, (4, 4)), lw=1)
    ax.text(0.505, n - 0.4, "coin flip", color=INK3, fontsize=9)
    ax.set_xlim(0.4, 1.02)
    ax.set_ylim(-0.6, n - 0.2)
    ax.set_xlabel("ROC AUC on the test set (higher is better)")
    ax.grid(axis="x", color=GRID)
    ax.set_axisbelow(True)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.legend(loc="upper center", bbox_to_anchor=(0.42, 1.17), ncol=(len(CHART) + 1) // 2, frameon=False, fontsize=10, handletextpad=0.3)
    fig.tight_layout()
    fig.savefig(OUT + "auc-by-slice.png", facecolor=PAPER)

    C = [("blocked", "Blocked", "#c23b3b", "white"), ("flagged", "Passed, flagged in the log", "#9aa6b1", "white"),
         ("passed", "Passed", "#d6dce1", INK)]
    short = {"Jev (cloud)": "Jev", "RSI-Jev v6.1-VL 4B": "RSI-Jev 4B (local)",
             "Nimble 9B 4-bit": "Nimble 4-bit (local)", "Tev1 4B": "Tev1 4B (local)",
             "Lux 9B MLX 4-bit": "Lux 4-bit (local)", "d1-3B": "d1-3B (local)",
             "SemIf Qwen3.5-4B 8-bit": "SemIf 8-bit", "Laya 421M": "Laya"}
    fig, ax = plt.subplots(figsize=(10, 1.0 + 0.36 * (len(short) * len(groups) + len(groups))), dpi=200)
    fig.patch.set_facecolor(PAPER)
    ys, labels, y = [], [], 0
    for gi, (g, _) in enumerate(groups):
        if gi:
            y -= 0.5
        for k in short:
            v = out["verdicts"][f"{k} | {g}"]
            left = 0
            for key, lab, col, tc in C:
                w = v[key]
                if w > 0:
                    ax.barh(y, w, left=left, color=col, height=0.72, edgecolor=PAPER, linewidth=1.5,
                            label=lab if (gi == 0 and k == "Jev (cloud)") else None)
                    if w >= 6:
                        ax.text(left + w / 2, y, f"{w:.1f}%", ha="center", va="center", color=tc, fontsize=9.5)
                    elif key in ("blocked", "passed"):  # small but important: named, outside the bar
                        ax.text(101, y, f"{w:.1f}% {key}", va="center", ha="left", color=INK2, fontsize=9)
                left += w
            ys.append(y)
            labels.append(f"{short[k]} · {g} ({v['n']})" if k == "Jev (cloud)" else f"{short[k]} · {g}")
            y -= 1
    ax.set_yticks(ys)
    ax.set_yticklabels(labels)
    ax.set_xlim(0, 116)
    ax.set_xlabel("Share of test items")
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
    ax.legend(loc="upper center", bbox_to_anchor=(0.45, 1.1), ncol=3, frameon=False, fontsize=10)
    fig.tight_layout()
    fig.savefig(OUT + "verdicts.png", facecolor=PAPER)
    print("charts written to", OUT)
