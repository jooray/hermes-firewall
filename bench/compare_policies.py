"""Deployable policies side by side. Everything fitted on dev, reported on test.

laya   : mean(imperative_to_reader, noul_injection) (the deployed rule)
semif  : best dev-AUC aggregation of SemIf's four questions
hybrid : SemIf for email/messages/posts (asynchronous, latency tolerant), Laya for web pages
Each: block at dev 1% FPR, warn at dev 5% FPR, hidden-content flags escalate to warn.
"""
import json, statistics, sys
from collections import Counter, defaultdict
from sklearn.metrics import roc_auc_score
from evaluate import load, scores, pick_threshold, aggregators, HIDING_FLAGS

dev, test = load("dev"), load("test")
L = {s: scores("laya_en", s) for s in ("dev", "test")}
S = {s: scores("semif", s) for s in ("dev", "test")}
SQ = ["addressed_ai", "override", "off_topic_task", "covert"]

def laya_fn(s): return (s["imperative_to_reader"] + s["noul_injection"]) / 2

# SemIf aggregation chosen on dev
best = None
for name, fn in aggregators(SQ).items():
    auc = roc_auc_score([dev[i]["label"] for i in dev], [fn(S["dev"][i]["text"]) for i in dev])
    if best is None or auc > best[1]:
        best = (name, auc, fn)
semif_name, semif_dev_auc, semif_fn = best

def thresholds(sc, fn):
    y = [dev[i]["label"] for i in dev]; v = [fn(sc["dev"][i]["text"]) for i in dev]
    pos = [a for a, l in zip(v, y) if l]; neg = [a for a, l in zip(v, y) if not l]
    return pick_threshold(pos, neg, 0.01), pick_threshold(pos, neg, 0.05), roc_auc_score(y, v)

tl = thresholds(L, laya_fn); ts = thresholds(S, semif_fn)
def web(r): return r["source"] == "web_page"

POL = {
    "laya": lambda i, r: (laya_fn(L["test"][i]["text"]), tl, L["test"][i]["text"]["ms"]),
    "semif": lambda i, r: (semif_fn(S["test"][i]["text"]), ts, S["test"][i]["text"]["ms"]),
    "hybrid": lambda i, r: ((laya_fn(L["test"][i]["text"]), tl, L["test"][i]["text"]["ms"]) if web(r)
                            else (semif_fn(S["test"][i]["text"]), ts, S["test"][i]["text"]["ms"])),
}
out = {"semif_agg": semif_name, "semif_dev_auc": semif_dev_auc, "laya_dev_auc": tl[2],
       "thresholds": {"laya": tl[:2], "semif": ts[:2]}, "policies": {}}
for pname, f in POL.items():
    tab = defaultdict(Counter); ys, vs = [], []; lat = defaultdict(list)
    for i, r in test.items():
        s, (blk, wrn, _), ms = f(i, r)
        hidden = bool(HIDING_FLAGS & set(r["flags"]))
        v = "block" if s >= blk else "warn" if (s >= wrn or hidden) else "pass"
        key = r["source"] if r["source"] != "carrier" else ("carrier_image" if r["kind"] == "image" else "carrier_text")
        tab[(key, r["label"])][v] += 1
        tab[("ALL", r["label"])][v] += 1
        ys.append(r["label"]); vs.append(s)
        lat[r["source"] if r["kind"] == "text" else "image"].append(ms + r.get("extract_ms", 0))
    out["policies"][pname] = {
        "auc": roc_auc_score(ys, vs),
        "verdicts": {f"{k}|{l}": dict(c) for (k, l), c in sorted(tab.items())},
        "latency_ms": {k: [statistics.median(v), sorted(v)[int(.95 * (len(v) - 1))]] for k, v in lat.items()},
    }
json.dump(out, open("results_policies.json", "w"), indent=1)
print("semif agg:", semif_name, "dev AUC %.3f" % semif_dev_auc, "| laya dev AUC %.3f" % tl[2])
for p, d in out["policies"].items():
    print(f"\n== {p}: test AUC {d['auc']:.3f}")
    for k, c in d["verdicts"].items():
        n = sum(c.values())
        print(f"  {k:22s} n={n:3d} block {c.get('block',0)/n:6.1%} warn {c.get('warn',0)/n:6.1%} pass {c.get('pass',0)/n:6.1%}")
    print("  latency (median, p95 ms):", {k: (round(a), round(b)) for k, (a, b) in d["latency_ms"].items()})
