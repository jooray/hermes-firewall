"""SemIf / Qwen3.5-4B over the full corpus (extracted text), same four v1 score questions as Laya.
Resumable: rows already in scores/semif_<split>.jsonl are skipped.
Run with decision-tools/Semif's venv:  ../decision-tools/Semif/.venv/bin/python score_semif.py"""
import json, os, sys, time
sys.path.insert(0, "../firewall/src")
import mlx.core as mx
from semif_phase1 import mlx_backend
from hermes_firewall.laya_detector import QUESTIONS, chunk_text

QS = {k: v for k, v in QUESTIONS.items() if v["type"] == "score"}
# SEMIF_MODEL / SEMIF_REVISION / SEMIF_BITS (4|8, in-memory affine quantization) / SEMIF_TAG
MODEL = os.environ.get("SEMIF_MODEL", "Qwen/Qwen3.5-4B")
REVISION = os.environ.get("SEMIF_REVISION", "851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a")
BITS = int(os.environ["SEMIF_BITS"]) if os.environ.get("SEMIF_BITS") else None
TAG = os.environ.get("SEMIF_TAG", "semif")
model, tokenizer, meta = mlx_backend.load_model(MODEL, REVISION, BITS)

def rows_for(chunk):
    return [{"id": q, "state": chunk, "question": d["instructions"],
             "options": [{"id": str(i), "description": c} for i, c in enumerate(d["criteria"])]}
            for q, d in QS.items()]

def score(text):
    best = dict.fromkeys(QS, 0.0)
    best["n_chunks"] = 0
    if not text.strip():
        return best
    for ch in chunk_text(text, 6000, 300)[:6]:
        rows = rows_for(ch)
        try:
            res, _ = mlx_backend.score_shared(model, tokenizer, rows, meta)
        except ValueError:  # shared-prefix check can fail on tokenization boundaries
            res = [mlx_backend.score(model, tokenizer, r, meta) for r in rows]
        for r in res:
            best[r["id"]] = max(best[r["id"]], r["probabilities"][-1])
        best["n_chunks"] += 1
    mx.clear_cache()
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
