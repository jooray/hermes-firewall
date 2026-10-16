"""Vega (vegaml 0.9, frozen Qwen3.5 + small physics engine) over the full corpus (extracted text),
same four v1 score questions as Laya/SemIf. Resumable: rows already in scores/<tag>_<split>.jsonl are skipped.
VEGA_SIZE=0.8b|4b, VEGA_TAG. Run niced with Vega's venv:
  nice -n 10 ../decision-tools/Vega/.venv/bin/python score_vega.py"""
import json, os, sys, time
sys.path.insert(0, "../firewall/src")
import torch
torch.set_num_threads(4)
import vegaml
from hermes_firewall.questions import QUESTIONS, chunk_text

QS = {k: {"question": d["instructions"], "options": d["criteria"], **d}
      for k, d in QUESTIONS.items() if d["type"] == "score"}
SIZE = os.environ.get("VEGA_SIZE", "0.8b")
TAG = os.environ.get("VEGA_TAG", f"vega-{SIZE}")
model = vegaml.load(SIZE)

def score(text):
    best = dict.fromkeys(QS, 0.0)
    best["n_chunks"] = 0
    if not text.strip():
        return best
    for ch in chunk_text(text, 6000, 300)[:6]:
        ans = model.decide(ch, QS)["answers"]
        for q in QS:
            best[q] = max(best[q], ans[q]["probs"]["2"])
        best["n_chunks"] += 1
    return best

for split in sys.argv[1:] or ["test", "dev"]:
    path = f"scores/{TAG}_{split}.jsonl"
    done = set()
    if os.path.exists(path):
        done = {json.loads(l)["id"] for l in open(path)}
    with open(path, "a") as out:
        for l in open(f"corpus/{split}.extracted.jsonl"):
            r = json.loads(l)
            if r["id"] in done:
                continue
            t = time.perf_counter()
            s = score(r["text"])
            s["ms"] = (time.perf_counter() - t) * 1000
            out.write(json.dumps({"id": r["id"], "text": s}) + "\n")
            out.flush()
    print(TAG, split, "done", flush=True)
