"""SemIf variants vs Laya: per-slice AUC, dev-fitted policy verdicts, latency, memory.
Writes results_variants.json and, with --write-policy TAG, the service policy for that variant."""
import json, re, statistics, sys
from collections import Counter
from sklearn.metrics import roc_auc_score
from evaluate import load, scores, pick_threshold, aggregators, HIDING_FLAGS

dev, test = load("dev"), load("test")
SQ = ["addressed_ai", "override", "off_topic_task", "covert"]
VARIANTS = {
    "laya_en": ("Laya 421M", None),
    "semif": ("SemIf Qwen3.5-4B BF16", SQ),
    "semif_q8": ("SemIf Qwen3.5-4B 8-bit", SQ),
    "semif_q4": ("SemIf Qwen3.5-4B 4-bit", SQ),
    "semif_minicpm": ("SemIf MiniCPM5-2B BF16", SQ),
    "jev": ("Jev (jev-latest, Venice cloud)", SQ + ["imperative_to_reader", "noul_injection", "choice_kind"]),
}
SLICES = {
    "planted_email": lambda r: r["source"] == "bipia_email",
    "deepset": lambda r: r["source"] == "deepset",
    "gandalf_vs_benign": lambda r: r["source"] == "gandalf" or r["label"] == 0,
    "carrier_text": lambda r: r["source"] == "carrier" and r["kind"] == "text",
    "carrier_image": lambda r: r["source"] == "carrier" and r["kind"] == "image",
    "attacks_vs_nostr": lambda r: r["label"] == 1 or r["source"] == "nostr",
    "all": lambda r: True,
}
mem = {}
try:
    for line in open("variants-mem.log"):
        t, v = line.split(); mem.setdefault(t, []).append(int(v.rstrip("%")))
except FileNotFoundError:
    pass

out = {}
for tag, (label, qs) in VARIANTS.items():
    d, t = scores(tag, "dev"), scores(tag, "test")
    if not d or not t or len(d) < len(dev) or len(t) < len(test):
        continue
    if qs is None:
        name, fn = "mean(imperative_to_reader,noul_injection)", lambda s: (s["imperative_to_reader"] + s["noul_injection"]) / 2
    else:
        best = max(aggregators(qs).items(), key=lambda kv: roc_auc_score([dev[i]["label"] for i in dev], [kv[1](d[i]["text"]) for i in dev]))
        name, fn = best
    y = [dev[i]["label"] for i in dev]; v = [fn(d[i]["text"]) for i in dev]
    pos = [a for a, l in zip(v, y) if l]; neg = [a for a, l in zip(v, y) if not l]
    blk2 = pick_threshold(pos, neg, 0.02); blk, wrn = pick_threshold(pos, neg, 0.01), pick_threshold(pos, neg, 0.05)
    res = {"label": label, "agg": name, "block": blk, "warn": wrn, "slices": {}}
    for sn, f in SLICES.items():
        ids = [i for i in test if f(test[i])]
        res["slices"][sn] = roc_auc_score([test[i]["label"] for i in ids], [fn(t[i]["text"]) for i in ids])
    ys = [test[i]["label"] for i in test]; vs = [fn(t[i]["text"]) for i in test]
    P = sum(ys); N = len(ys) - P
    res["tpr_at_dev2"] = sum(a >= blk2 for a, l in zip(vs, ys) if l) / P
    res["fpr_at_dev2"] = sum(a >= blk2 for a, l in zip(vs, ys) if not l) / N
    verd = {1: Counter(), 0: Counter(), "email1": Counter(), "email0": Counter()}
    for i in test:
        r = test[i]; s = fn(t[i]["text"])
        vv = "block" if s >= blk else "warn" if (s >= wrn or HIDING_FLAGS & set(r["flags"])) else "pass"
        verd[r["label"]][vv] += 1
        if r["source"] == "bipia_email":
            verd[f"email{r['label']}"][vv] += 1
    res["verdicts"] = {str(k): {kk: c[kk] / sum(c.values()) for kk in ("block", "warn", "pass")} for k, c in verd.items()}
    ms = [t[i]["text"]["ms"] for i in test if test[i]["kind"] == "text" and test[i]["source"] != "web_page"]
    wp = [t[i]["text"]["ms"] for i in test if test[i]["source"] == "web_page"]
    res["latency_ms"] = {"message_p50": statistics.median(ms), "message_p95": sorted(ms)[int(.95 * (len(ms) - 1))], "web_page_p50": statistics.median(wp)}
    if tag in mem:
        res["min_free_pct"] = min(mem[tag])
    out[tag] = res
json.dump(out, open("results_variants.json", "w"), indent=1)
for tag, r in out.items():
    print(f"{r['label']:26s} agg={r['agg'][:34]:34s} AUC {r['slices']['all']:.3f} email {r['slices']['planted_email']:.3f} "
          f"caught@dev2% {r['tpr_at_dev2']:.1%} fp {r['fpr_at_dev2']:.1%} | block atk {r['verdicts']['1']['block']:.1%} ben {r['verdicts']['0']['block']:.1%} "
          f"| msg {r['latency_ms']['message_p50']:.0f}ms page {r['latency_ms']['web_page_p50']/1000:.1f}s | free min {r.get('min_free_pct','?')}%")

if "--write-policy" in sys.argv:
    tag = sys.argv[sys.argv.index("--write-policy") + 1]
    r = out[tag]
    m = re.match(r"(mean|max)\((.*)\)", r["agg"])
    agg, qs = (m.group(1), m.group(2).split(",")) if m else ("max", [r["agg"]])
    bits = {"semif_q8": 8, "semif_q4": 4}.get(tag)
    backend = "jev" if tag == "jev" else "semif"
    pol = {"backend": backend, "questions": qs, "agg": agg, "block": r["block"], "warn": r["warn"],
           "hiding_escalates": True, "bits": bits,
           "model": "openbmb/MiniCPM5-2B" if tag == "semif_minicpm" else "",
           "revision": "12a3808a956f869c767195e9266b59c4d21d92e2" if tag == "semif_minicpm" else "",
           "fitted_on": f"bench dev split ({tag}), block@1% warn@5% dev FPR"}
    json.dump(pol, open(f"../firewall/src/hermes_firewall/policy-{backend}.json", "w"), indent=1)
    print(f"wrote policy-{backend}.json", pol)
