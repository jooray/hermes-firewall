"""Image carriers: d1 models given the OCR text (score_ollama.py, the plugin's path) vs the picture itself
plus metadata text (score_d1_images.py). AUC on the test image items, overall and split into text drawn in
the pixels (img_visible / img_lowcontrast / img_tiny) and text hidden in metadata (EXIF, XMP, JPEG comment,
trailing bytes, PNG text); plain photos count as benign in both. Blocked = at or above the model's block
threshold refitted on its own text dev scores (as in compare_local_sysone.py). Writes results_d1_images.json.
"""
import json
import sys

from sklearn.metrics import roc_auc_score

from evaluate import load, pick_threshold, scores

sys.path.insert(0, "../firewall/src")
from hermes_firewall.policy import Policy  # noqa: E402

jev = Policy.load(None, "jev")
dev, test = load("dev"), load("test")
PIXEL = {"img_visible", "img_lowcontrast", "img_tiny"}
GROUPS = {"all image items": lambda r: True,
          "text in pixels": lambda r: r["category"] in PIXEL or r["category"] == "plain_photo",
          "text in metadata": lambda r: r["category"] not in PIXEL}
out = {}
for model, tag in {"d1-3B": "d1-3b", "d1-omni-600M": "d1-omni-600m", "RSI-Jev v6.1-VL 4B": "rsi-jev-v6.1-vl-4b"}.items():
    sd = scores(tag, "dev")
    st = scores(tag + "_img", "test")
    if not sd or not st:
        continue
    v = [(jev.score(sd[i]["text"]), dev[i]["label"]) for i in sd]
    block = pick_threshold([a for a, l in v if l], [a for a, l in v if not l], 0.01)
    for mode, t in {"OCR text": tag, "picture": tag + "_img"}.items():
        st = scores(t, "test")
        ids = [i for i in st if test[i].get("kind") == "image"]
        for g, f in GROUPS.items():
            sel = [i for i in ids if f(test[i])]
            y = [test[i]["label"] for i in sel]
            s = [jev.score(st[i]["text"]) for i in sel]
            out[f"{model} | {mode} | {g}"] = {
                "n": len(sel), "attacks": sum(y), "auc": roc_auc_score(y, s),
                "attacks_blocked": sum(a >= block for a, l in zip(s, y) if l),
                "benign_blocked": sum(a >= block for a, l in zip(s, y) if not l), "block": block}
json.dump(out, open("results_d1_images.json", "w"), indent=1)
for k, v in out.items():
    print(f"{k:55s} n={v['n']:3d} AUC {v['auc']:.3f}  blocked {v['attacks_blocked']}/{v['attacks']} attacks, {v['benign_blocked']} benign")
