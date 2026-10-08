"""Can a local System One model (Ollama 0.35: Nimble 9B, Tev1 4B / 0.8B) replace jev-latest?

Every model is scored by score_jev.py / score_ollama.py through the plugin's Jev client with the
deployed two questions, then judged like blog_charts.py: same 718 test items (dev duplicates and
rows changed after older scoring left out), deployed aggregation (max of the two questions).
Two policies per model: Jev's shipped thresholds as they are, and thresholds refitted on that
model's own dev scores (block @1% / warn @5% dev FPR, like policy-jev.json). Writes
results_local_sysone.json.
"""
import json
import sys

from sklearn.metrics import roc_auc_score

from evaluate import HIDING_FLAGS, dev_duplicates, load, pick_threshold, scores

sys.path.insert(0, "../firewall/src")
from hermes_firewall.policy import Policy  # noqa: E402

MODELS = {"Jev jev-latest (Venice)": "jev_deployed", "Nimble 9B Q8_0": "ollama_nimble-9b", "Nimble 9B Q4_K_M": "ollama_nimble-9b-q4_K_M",
          "Tev1 4B": "ollama_tev1-4b", "Tev1 0.8B": "ollama_tev1-0.8b",
          "Lux 9B MLX 4-bit": "mlx_lux-9b-4bit", "d1-3B": "d1-3b", "d1-omni-600M": "d1-omni-600m",
          "RSI-Jev v6.1-VL 4B": "rsi-jev-v6.1-vl-4b"}
MODELS = {k: v for k, v in MODELS.items() if scores(v, "test") and scores(v, "dev")}
dev, test = load("dev"), load("test")
try:
    changed = set(json.load(open("corpus/test.changed_v5.json")))
except FileNotFoundError:
    changed = set()
jev = Policy.load(None, "jev")
S = {k: scores(t, "test") for k, t in MODELS.items()}
SD = {k: scores(t, "dev") or {} for k, t in MODELS.items()}
ids = sorted(set(test) - dev_duplicates(dev, test) - changed)
ids = [i for i in ids if all(i in S[k] for k in MODELS)]
SLICES = {
    "Overall": lambda r: True,
    "Planted instruction in email (BIPIA)": lambda r: r["source"] == "bipia_email",
    "Direct injections (deepset)": lambda r: r["source"] == "deepset",
    "Gandalf vs all benign": lambda r: r["source"] == "gandalf" or r["label"] == 0,
    "Markup carriers (attributes, scripts)": lambda r: r["source"] == "carrier" and r["category"].startswith("attr_"),
    "Image carriers": lambda r: r["source"] == "carrier" and r["kind"] == "image",
    "All attacks vs Nostr posts": lambda r: r["label"] == 1 or r["source"] == "nostr",
    "All attacks vs web pages": lambda r: r["label"] == 1 or r["source"] == "web_page",
}
GROUPS = {"all attacks": lambda r: r["label"] == 1,
          "planted email": lambda r: r["source"] == "bipia_email" and r["label"] == 1,
          "benign": lambda r: r["label"] == 0}


def verdicts(pol, sc):
    out = {}
    for g, f in GROUPS.items():
        sel = [i for i in ids if f(test[i])]
        c = {"injection": 0, "suspicious": 0, "safe": 0}
        for i in sel:
            c[pol.decide(sc[i]["text"], [x for x in test[i]["flags"] if x in HIDING_FLAGS])["verdict"]] += 1
        out[g] = {"n": len(sel), "blocked": c["injection"], "flagged": c["suspicious"], "passed": c["safe"]}
    return out


out = {"n_test": len(ids), "attacks": sum(test[i]["label"] for i in ids), "models": {}}
ys = [test[i]["label"] for i in ids]
for k in MODELS:
    vs = [jev.score(S[k][i]["text"]) for i in ids]
    m = {"auc": {n: roc_auc_score([test[i]["label"] for i in ids if f(test[i])],
                                  [jev.score(S[k][i]["text"]) for i in ids if f(test[i])]) for n, f in SLICES.items()}}
    d_ids = [i for i in dev if i in SD[k]]
    if d_ids:
        dv = [jev.score(SD[k][i]["text"]) for i in d_ids]
        dy = [dev[i]["label"] for i in d_ids]
        pos, neg = [a for a, l in zip(dv, dy) if l], [a for a, l in zip(dv, dy) if not l]
        thr = pick_threshold(pos, neg, 0.02)
        m["dev_n"] = len(d_ids)
        m["dev_auc"] = roc_auc_score(dy, dv)
        m["tpr_at_dev2"] = sum(a >= thr for a, l in zip(vs, ys) if l) / sum(ys)
        m["fpr_at_dev2"] = sum(a >= thr for a, l in zip(vs, ys) if not l) / (len(ys) - sum(ys))
        refit = Policy(**(jev.describe() | {"block": float(pick_threshold(pos, neg, 0.01)),
                                            "warn": float(pick_threshold(pos, neg, 0.05))}))
        m["refit"] = {"block": refit.block, "warn": refit.warn, "verdicts": verdicts(refit, S[k])}
    m["jev_thresholds"] = verdicts(jev, S[k])
    ms = [S[k][i]["text"]["ms"] for i in ids]
    m["ms_p50"] = sorted(ms)[len(ms) // 2]
    m["ms_p95"] = sorted(ms)[int(0.95 * (len(ms) - 1))]
    m["errors_test"] = sum(1 for l in open(f"scores/{MODELS[k]}_test.jsonl") if '"error"' in l)
    out["models"][k] = m
json.dump(out, open("results_local_sysone.json", "w"), indent=1)
print(json.dumps(out, indent=1))
