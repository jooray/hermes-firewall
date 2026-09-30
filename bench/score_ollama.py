"""Local System One models (Nimble, Tev1) via Ollama's /v1/systemone, scored through the plugin's
own Jev client: Ollama's endpoint takes the same request (model, state, questions) and returns the
same answers, so JevDetector only needs a different URL and model name. Same questions as the
deployed Jev backend. Chunks default to Jev's 12,000 characters; Ollama rejects (HTTP 400, never
truncates) a prompt longer than the model's shipped num_ctx (Tev1: 2,050 tokens, Nimble: 8,194),
so a model with a short context needs --chunk-chars small enough to fit (~300 tokens of prompt
overhead per question plus the chunk).

    uv run python score_ollama.py MODEL [--chunk-chars N] [--tag NAME] [split ...]

e.g. `score_ollama.py nimble:9b` writes scores/ollama_nimble-9b_{test,dev}.jsonl. Rows carry the
sha256 of the scored text; a rerun skips rows whose id and sha match. Rows that cannot be scored
are written as {"id", "sha", "error"}.
"""
import argparse
import hashlib
import json
import os
from importlib.resources import files

from hermes_firewall.jev_detector import JevDetector

ap = argparse.ArgumentParser()
ap.add_argument("model")
ap.add_argument("--tag")
ap.add_argument("--chunk-chars", type=int, default=12000)
ap.add_argument("--url", default="http://127.0.0.1:11434/v1/systemone")
ap.add_argument("splits", nargs="*", default=["test", "dev"])
args = ap.parse_args()
tag = args.tag or "ollama_" + args.model.replace(":", "-")
qs = json.loads(files("hermes_firewall").joinpath("policy-jev.json").read_text())["questions"]
# workers=1: Ollama scores one request at a time per loaded model anyway
det = JevDetector("local", model=args.model, questions=qs, timeout=300, attempts=3, workers=1, url=args.url,
                 chunk_chars=args.chunk_chars, overlap=min(400, args.chunk_chars // 10))


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def score(r):
    try:
        return {"id": r["id"], "sha": sha(r["text"]), "text": det.score_many([r["text"]])[0]}
    except Exception as e:
        return {"id": r["id"], "sha": sha(r["text"]), "error": f"{type(e).__name__}: {e}"[:200]}


for split in args.splits:
    path = f"scores/{tag}_{split}.jsonl"
    rows = [json.loads(l) for l in open(f"corpus/{split}.extracted.jsonl")]
    want = {r["id"]: sha(r["text"]) for r in rows}
    kept = []
    if os.path.exists(path):
        kept = [s for s in map(json.loads, open(path)) if "error" not in s and want.get(s["id"]) == s.get("sha")]
    done = {s["id"] for s in kept}
    todo = [r for r in rows if r["id"] not in done]
    errors = 0
    with open(path, "w") as out:
        out.writelines(json.dumps(s) + "\n" for s in kept)
        out.flush()
        for n, r in enumerate(todo, 1):
            res = score(r)
            errors += "error" in res
            out.write(json.dumps(res) + "\n")
            out.flush()
            if n % 100 == 0:
                print(tag, split, n, "/", len(todo), "errors", errors, flush=True)
    print(tag, split, "scored", len(todo), "kept", len(kept), "errors", errors, flush=True)
