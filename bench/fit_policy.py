"""Fit the deployed policy on dev only: logistic regression over Laya signals, with a block
threshold at BLOCK_FPR and a warn threshold at WARN_FPR (both on dev benign). Writes
../firewall/src/hermes_firewall/policy.json and reports the frozen policy's verdicts on test."""
import json, math
from collections import Counter, defaultdict
from evaluate import load, scores, pick_threshold

BLOCK_FPR, WARN_FPR = 0.01, 0.05
dev, test = load("dev"), load("test")
L = {"dev": scores("laya_en", "dev"), "test": scores("laya_en", "test")}
QS = [q for q in ("addressed_ai", "override", "off_topic_task", "covert", "imperative_to_reader", "noul_injection", "choice_kind")]
# A dev-fitted logistic regression put negative weights on two questions and then scored
# the textbook "Ignore all previous instructions..." as safe. Deployed rule: the plain mean
# of the two questions that was the best-AUC aggregation on dev (evaluate.py), which is
# monotone and has nothing to overfit except two thresholds.
QS = ["imperative_to_reader", "noul_injection"]
y = [dev[i]["label"] for i in dev]
p = [sum(L["dev"][i]["text"][q] for q in QS) / len(QS) for i in dev]
neg = [v for v, l in zip(p, y) if not l]; pos = [v for v, l in zip(p, y) if l]
block, warn = pick_threshold(pos, neg, BLOCK_FPR), pick_threshold(pos, neg, WARN_FPR)
pol = {"questions": QS, "agg": "mean", "block": float(block), "warn": float(warn),
       "hiding_escalates": True, "fitted_on": f"bench dev split, block@{BLOCK_FPR:.0%} warn@{WARN_FPR:.0%} dev FPR"}
pol["backend"] = "laya"
json.dump(pol, open("../firewall/src/hermes_firewall/policy-laya.json", "w"), indent=1)
print(json.dumps(pol, indent=1))

import sys; sys.path.insert(0, "../firewall/src")
from hermes_firewall.policy import Policy
P = Policy(**pol)
tab = defaultdict(Counter)
for i, r in test.items():
    v = P.decide(L["test"][i]["text"], r["flags"])["verdict"]
    key = f"{r['source']}{'/'+r['category'] if r['source']=='carrier' else ''} [{'ATTACK' if r['label'] else 'benign'}]"
    tab[key][v] += 1
json.dump({k: dict(v) for k, v in tab.items()}, open("results_policy_test.json", "w"), indent=1)
tot = defaultdict(Counter)
for k, c in sorted(tab.items()):
    print(f"{k:42s} block {c['injection']:3d}  warn {c['suspicious']:3d}  pass {c['safe']:3d}")
    tot["ATTACK" in k].update(c)
for lab, c in tot.items():
    n = sum(c.values())
    print("ATTACKS" if lab else "BENIGN ", f"n={n} block {c['injection']/n:.1%} warn {c['suspicious']/n:.1%} pass {c['safe']/n:.1%}")
