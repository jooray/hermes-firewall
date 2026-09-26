"""Fit on dev, report on test.

For each detector: pick the aggregation (for multi-question detectors) with the
best dev ROC-AUC, then the threshold that keeps dev false positives at or
below FPR_BUDGET. Both are frozen and applied to test. Also reports the
structural-flag policy ("hidden text present => at least suspicious").
"""

import json
import statistics
import sys
from collections import defaultdict
from itertools import combinations

from sklearn.metrics import roc_auc_score

FPR_BUDGET = float(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1][0].isdigit() else 0.02
QS = ["addressed_ai", "override", "off_topic_task", "covert", "imperative_to_reader", "noul_injection", "choice_kind"]
from hermes_firewall.policy import HIDING_FLAGS as _HF
HIDING_FLAGS = set(_HF)  # the deployed list, so benchmark verdicts match production


def load(split):
    return {r["id"]: r for r in map(json.loads, open(f"corpus/{split}.extracted.jsonl"))}


def _is_error(r):
    # "unscorable": an older jev file stored a failed item as all-1.0 scores. An error is an
    # operational failure, not a detection, so it is excluded and reported separately.
    return "error" in r or bool(r.get("text", {}).get("unscorable"))


def scores(name, split):
    """Scored rows only; failed rows are left out (see score_errors)."""
    try:
        return {r["id"]: r for r in map(json.loads, open(f"scores/{name}_{split}.jsonl")) if not _is_error(r)}
    except FileNotFoundError:
        return None


def score_errors(name, split):
    try:
        return [r["id"] for r in map(json.loads, open(f"scores/{name}_{split}.jsonl")) if _is_error(r)]
    except FileNotFoundError:
        return []


def dev_duplicates(dev, test):
    """Test ids whose extracted text (the detector's input) also occurs in dev: identical input,
    identical score, so they measure nothing the dev fit has not already seen."""
    seen = {r["text"] for r in dev.values()}
    return {i for i, r in test.items() if r["text"] in seen}


def aggregators(QS):
    aggs = {"maxall": lambda s: max(s[q] for q in QS), "meanall": lambda s: sum(s[q] for q in QS) / len(QS)}
    for q in QS:
        aggs[q] = (lambda q: lambda s: s[q])(q)
    for a, b in combinations(QS, 2):
        aggs[f"max({a},{b})"] = (lambda a, b: lambda s: max(s[a], s[b]))(a, b)
        aggs[f"mean({a},{b})"] = (lambda a, b: lambda s: (s[a] + s[b]) / 2)(a, b)
    return aggs


def pick_threshold(pos, neg, budget):
    cands = sorted(set(neg + pos + [1.01]))
    best = 1.01
    for t in cands:
        fpr = sum(x >= t for x in neg) / max(1, len(neg))
        if fpr <= budget:
            best = t
            break
    return best


def fit(name, dev_rows, dev_sc, field):
    ids = [i for i in dev_rows if i in dev_sc]
    y = [dev_rows[i]["label"] for i in ids]
    sample = dev_sc[ids[0]][field]
    if "p" in sample:
        aggs = {"p": lambda s: s["p"]}
    else:
        aggs = aggregators([q for q in QS if q in sample])
    best = None
    for an, fn in aggs.items():
        vals = [fn(dev_sc[i][field]) for i in ids]
        try:
            auc = roc_auc_score(y, vals)
        except ValueError:
            auc = 0.5
        if best is None or auc > best[1]:
            best = (an, auc, fn, vals)
    an, auc, fn, vals = best
    pos = [v for v, l in zip(vals, y) if l]
    neg = [v for v, l in zip(vals, y) if not l]
    thr = pick_threshold(pos, neg, FPR_BUDGET)
    return an, auc, fn, thr


def report(name, field, fn, thr, rows, sc, flags_policy=False):
    ids = [i for i in rows if i in sc]
    y, v, pred = [], [], []
    per = defaultdict(lambda: [0, 0])  # key -> [flagged, total]
    ms = defaultdict(list)
    for i in ids:
        r = rows[i]
        s = fn(sc[i][field])
        p = s >= thr or (flags_policy and bool(HIDING_FLAGS & set(r["flags"])))
        y.append(r["label"]); v.append(s); pred.append(p)
        key = (r["source"], r["category"] if r["source"] == "carrier" else "", r["label"])
        per[key][0] += p
        per[key][1] += 1
        ms[r["source"] if r["kind"] == "text" else "image"].append(sc[i][field].get("ms", 0) + (r.get("extract_ms", 0) if field == "text" else 0))
    tp = sum(p and l for p, l in zip(pred, y)); fp = sum(p and not l for p, l in zip(pred, y))
    P = sum(y); N = len(y) - P
    try:
        auc = roc_auc_score(y, v)
    except ValueError:
        auc = float("nan")
    return dict(detector=name, field=field, flags=flags_policy, thr=thr, auc=auc,
                tpr=tp / P, fpr=fp / N, precision=tp / max(1, tp + fp),
                per={f"{k[0]}|{k[1]}|{k[2]}": f"{a}/{b}" for k, (a, b) in sorted(per.items())},
                latency={k: (statistics.median(x), sorted(x)[int(0.95 * (len(x) - 1))]) for k, x in ms.items()})


FLAG_FEATS = sorted(HIDING_FLAGS | {"image_metadata_text"})


def combined(dev, test):
    """Logistic regression over Laya signals + extraction flags (+ DeBERTa), fitted on dev only."""
    from sklearn.linear_model import LogisticRegression

    laya = {s: scores("laya_en", s) for s in ("dev", "test")}
    deb = {s: scores("deberta", s) for s in ("dev", "test")}
    if not laya["dev"] or not laya["test"]:
        return []
    qs = [q for q in QS if q in next(iter(laya["dev"].values()))["text"]]
    res = []
    for tag, use_deb in (("laya+flags (LR)", False), ("laya+deberta+flags (LR)", True)):
        if use_deb and not deb["dev"]:
            continue

        def feats(split, rows, i):
            f = [laya[split][i]["text"][q] for q in qs] + [float(x in rows[i]["flags"]) for x in FLAG_FEATS]
            if use_deb:
                f.append(deb[split][i]["text"]["p"])
            return f
        ids = list(dev)
        X = [feats("dev", dev, i) for i in ids]
        y = [dev[i]["label"] for i in ids]
        lr = LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced").fit(X, y)
        dv = lr.predict_proba(X)[:, 1]
        thr = pick_threshold([v for v, l in zip(dv, y) if l], [v for v, l in zip(dv, y) if not l], FPR_BUDGET)
        tsc = {i: {"text": {"p": float(lr.predict_proba([feats("test", test, i)])[0, 1]),
                            "ms": laya["test"][i]["text"]["ms"] + (deb["test"][i]["text"]["ms"] if use_deb else 0)}}
               for i in test}
        r = report(tag, "text", lambda s: s["p"], thr, test, tsc)
        r.update(agg="logistic", dev_auc=roc_auc_score(y, dv),
                 coef=dict(zip(qs + FLAG_FEATS + (["deberta"] if use_deb else []), map(float, lr.coef_[0]))))
        res.append(r)
    return res


def main():
    dev, test = load("dev"), load("test")
    out = []
    for name in ("regex", "deberta_noid", "laya_en_v1", "laya_multi_v1", "laya_en_noid", "deberta", "laya_en", "semif"):
        dsc, tsc = scores(name, "dev"), scores(name, "test")
        if not dsc or not tsc:
            continue
        for field in ("raw", "text"):
            if field not in next(iter(tsc.values())):
                continue
            an, dauc, fn, thr = fit(name, dev, dsc, field)
            res = report(name, field, fn, thr, test, tsc)
            res.update(agg=an, dev_auc=dauc)
            out.append(res)
            if field == "text":
                r2 = report(name, field, fn, thr, test, tsc, flags_policy=True)
                r2.update(agg=an, dev_auc=dauc)
                out.append(r2)
    out += combined(dev, test)
    json.dump(out, open(f"results_fpr{FPR_BUDGET}.json", "w"), indent=1)
    print(f"dev FPR budget {FPR_BUDGET:.0%}\n")
    print(f"{'detector':12s} {'input':9s} {'flags':5s} {'agg':30s} {'devAUC':>6s} {'AUC':>6s} {'TPR':>6s} {'FPR':>6s} {'prec':>6s}")
    for r in out:
        print(f"{r['detector']:12s} {('extracted' if r['field']=='text' else 'raw'):9s} {str(r['flags'])[0]:5s} {r['agg'][:30]:30s} "
              f"{r['dev_auc']:6.3f} {r['auc']:6.3f} {r['tpr']:6.1%} {r['fpr']:6.1%} {r['precision']:6.1%}")
    print()
    for r in out:
        if r["field"] == "text":
            print(r["detector"], "flags" if r["flags"] else "", json.dumps(r["per"]))
            print("   latency ms (median, p95):", {k: (round(a), round(b)) for k, (a, b) in r["latency"].items()})


if __name__ == "__main__":
    main()
