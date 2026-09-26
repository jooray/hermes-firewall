"""Does Jev's answer depend on which other questions share the request?

jev7:          all seven questions in one request (how the benchmark used to score Jev)
jev_deployed:  only the policy's questions in one request (what the plugin sends)

Same items, same aggregation (the deployed policy's), thresholds fitted on dev (block at 1% dev FPR,
warn at 5%, and a single threshold at 2% for "caught at ~dev 2%"). Reported on test, in full and
without test items whose extracted text also occurs in dev. Failed items are excluded and counted.
With --write-policy, writes policy-jev.json refitted on jev_deployed dev scores.
Writes results_jev_questions.json.
"""
import json
import statistics
import sys
from collections import Counter
from importlib.resources import files

from sklearn.metrics import roc_auc_score

from evaluate import HIDING_FLAGS, dev_duplicates, load, pick_threshold, score_errors, scores

POL = json.loads(files("hermes_firewall").joinpath("policy-jev.json").read_text())
QS, AGG = POL["questions"], POL["agg"]
fn = (lambda s: max(s[q] for q in QS)) if AGG == "max" else (lambda s: sum(s[q] for q in QS) / len(QS))
dev, test = load("dev"), load("test")
dup = dev_duplicates(dev, test)
tags = ["jev7", "jev_deployed"]
S = {t: {sp: scores(t, sp) for sp in ("dev", "test")} for t in tags}
common = {sp: set.intersection(*(set(S[t][sp]) for t in tags)) for sp in ("dev", "test")}
out = {"questions": QS, "agg": AGG, "dev_duplicates_in_test": len(dup),
       "dup_by_source": dict(Counter(f"{test[i]['source']}/{test[i]['label']}" for i in dup)),
       "errors": {t: {sp: score_errors(t, sp) for sp in ("dev", "test")} for t in tags}, "results": {}}


def evaluate(tag, test_ids):
    d_ids = sorted(common["dev"])
    y = [dev[i]["label"] for i in d_ids]
    v = [fn(S[tag]["dev"][i]["text"]) for i in d_ids]
    pos = [a for a, l in zip(v, y) if l]
    neg = [a for a, l in zip(v, y) if not l]
    blk, wrn, one = pick_threshold(pos, neg, 0.01), pick_threshold(pos, neg, 0.05), pick_threshold(pos, neg, 0.02)
    ids = sorted(test_ids)
    ys = [test[i]["label"] for i in ids]
    vs = [fn(S[tag]["test"][i]["text"]) for i in ids]
    verd = {1: Counter(), 0: Counter()}
    for i, s in zip(ids, vs):
        hidden = HIDING_FLAGS & set(test[i]["flags"])
        verd[test[i]["label"]]["block" if s >= blk else "flag" if (s >= wrn or hidden) else "pass"] += 1
    P, N = sum(ys), len(ys) - sum(ys)
    email = [(test[i]["label"], s) for i, s in zip(ids, vs) if test[i]["source"] == "bipia_email"]
    return {"n": len(ids), "attacks": P, "benign": N, "auc": roc_auc_score(ys, vs),
            "planted_email_auc": roc_auc_score([l for l, _ in email], [s for _, s in email]),
            "block": blk, "warn": wrn, "tpr_at_dev2": sum(s >= one for s, l in zip(vs, ys) if l) / P,
            "fpr_at_dev2": sum(s >= one for s, l in zip(vs, ys) if not l) / N,
            "verdicts": {("attacks" if k else "benign"): dict(c) for k, c in verd.items()}}


for tag in tags:
    out["results"][tag] = {"full": evaluate(tag, common["test"]), "dedup": evaluate(tag, common["test"] - dup)}
a = [fn(S["jev7"]["test"][i]["text"]) for i in sorted(common["test"])]
b = [fn(S["jev_deployed"]["test"][i]["text"]) for i in sorted(common["test"])]
diffs = [abs(x - y) for x, y in zip(a, b)]
out["per_item_abs_diff"] = {"median": statistics.median(diffs), "p95": sorted(diffs)[int(.95 * (len(diffs) - 1))],
                            "max": max(diffs), "over_0.1": sum(d > 0.1 for d in diffs), "n": len(diffs)}
json.dump(out, open("results_jev_questions.json", "w"), indent=1)

print(f"policy {AGG}({','.join(QS)}); test items in both: {len(common['test'])}; dev duplicates in test: {len(dup)} {out['dup_by_source']}")
print("errors:", {t: {sp: len(e) for sp, e in v.items()} for t, v in out["errors"].items()})
print("per-item |7q - 2q| on test:", out["per_item_abs_diff"])
for tag in tags:
    for k, r in out["results"][tag].items():
        va, vb = r["verdicts"]["attacks"], r["verdicts"]["benign"]
        print(f"{tag:13s} {k:5s} n={r['n']} AUC {r['auc']:.3f} email {r['planted_email_auc']:.3f} "
              f"caught@dev2% {r['tpr_at_dev2']:.1%} (fp {r['fpr_at_dev2']:.1%}) | block {r['block']:.3f} warn {r['warn']:.3f} | "
              f"attacks block/flag/pass {va.get('block', 0)}/{va.get('flag', 0)}/{va.get('pass', 0)} "
              f"benign {vb.get('block', 0)}/{vb.get('flag', 0)}/{vb.get('pass', 0)}")

if "--write-policy" in sys.argv:
    r = out["results"]["jev_deployed"]["full"]
    pol = dict(POL, block=r["block"], warn=r["warn"],
               fitted_on="bench dev split (jev_deployed: policy questions only, one request), block@1% warn@5% dev FPR")
    path = "../firewall/src/hermes_firewall/policy-jev.json"
    json.dump(pol, open(path, "w"), indent=1)
    print("wrote", path, pol)
