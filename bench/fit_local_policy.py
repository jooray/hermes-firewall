"""Policies for local System One models behind the plugin's "nimble" backend.

The backend is any server that speaks Jev's /v1/systemone: Ollama 0.35+ (Nimble, Tev1) or
RSI-Jev (rsi-jev serve). Same questions and aggregation as policy-jev.json; thresholds fitted
on the model's own dev scores (scores/<tag>_dev.jsonl from score_ollama.py): block at 1% and
warn at 5% dev FPR, as for Jev. local_block (the plugin's level for local files and shell
output, 0.6 for Jev) is set to the score with the same dev FPR as 0.6 has under Jev, so it
means the same strictness on this model. Writes ../firewall/src/hermes_firewall/policy-<model>.json
(":" -> "-"); run sync_core.sh after.

    uv run python fit_local_policy.py nimble:9b-q4_K_M nimble:9b
    uv run python fit_local_policy.py --tag rsi-jev-v6.1-vl-4b rsi-jev-v6.1-vl-4b
    uv run python fit_local_policy.py --tag d3-27b-q4 --dedup --block-midgap 0.005 d3-27b-q4

--dedup counts identical dev texts once. The dev split holds one three-word Nostr event
("channel:__roster", 40 copies, 6.6% of benign dev); a model that scores it high gets its 1%
and 5% thresholds pinned to that one value. --block-midgap B fits block at B dev FPR and then
moves it to the middle of the gap between the benign dev scores just below and just above it,
so it does not sit a rounding error above a benign text that recurs (d3 27B: the roster event
scores 0.8936 and the plain fit is 0.89372; mid-gap 0.908).
"""
import argparse
import json
from importlib.resources import files

from evaluate import load, pick_threshold, scores

ap = argparse.ArgumentParser()
ap.add_argument("models", nargs="+")
ap.add_argument("--tag", help="score tag of the first model (default ollama_<model>); needs exactly one model")
ap.add_argument("--dedup", action="store_true", help="count identical dev texts once")
ap.add_argument("--block-midgap", type=float, metavar="FPR",
                help="block at this dev FPR, moved to the middle of the benign-score gap it falls in")
args = ap.parse_args()
if args.tag and len(args.models) != 1:
    ap.error("--tag takes exactly one model")

dev = load("dev")
jev = json.loads(files("hermes_firewall").joinpath("policy-jev.json").read_text())


def agg(sig):
    return max(sig[q] for q in jev["questions"])


def split(tag, dedup=False):
    s, seen, v = scores(tag, "dev"), set(), []
    for i in dev:
        if i in s and not (dedup and dev[i]["text"] in seen):
            seen.add(dev[i]["text"])
            v.append((agg(s[i]["text"]), dev[i]["label"]))
    return [a for a, l in v if l], [a for a, l in v if not l]


def midgap(pos, neg, fpr):
    t = pick_threshold(pos, neg, fpr)
    below = [x for x in neg if x < t]
    above = [x for x in neg if x >= t]
    if not below or not above:
        return t
    return (max(below) + min(above)) / 2


_, jneg = split("jev_deployed")
local_fpr = sum(x >= 0.6 for x in jneg) / len(jneg)
for model in args.models:
    name = model.replace(":", "-")
    tag = args.tag or f"ollama_{name}"
    pos, neg = split(tag, args.dedup)
    block = midgap(pos, neg, args.block_midgap) if args.block_midgap else pick_threshold(pos, neg, 0.01)
    rule = (f"block mid-gap around {args.block_midgap:.1%}" if args.block_midgap else "block@1%") + \
        " warn@5% dev FPR" + (", identical dev texts counted once" if args.dedup else "")
    pol = {"backend": "nimble", "model": model, "questions": jev["questions"], "agg": jev["agg"],
           "block": float(block), "warn": float(pick_threshold(pos, neg, 0.05)),
           "local_block": float(pick_threshold(pos, neg, local_fpr)),
           "hiding_escalates": True, "bits": None, "revision": "",
           "fitted_on": f"bench dev split ({tag}, Jev-compatible /v1/systemone, policy-jev questions), "
                        f"{rule}, local_block@{local_fpr:.1%} dev FPR (= Jev at 0.6)"}
    path = f"../firewall/src/hermes_firewall/policy-{name}.json"
    json.dump(pol, open(path, "w"), indent=1)
    print(path, json.dumps(pol))
