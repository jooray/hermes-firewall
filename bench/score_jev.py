"""Jev (TypeSafe System One) via Venice /api/v1/decisions, scored through the plugin's own client
(hermes_firewall.jev_detector.JevDetector): same questions in one request, same chunking, same
handling of HTTP 500. What is measured is what is deployed.

    uv run python score_jev.py [--questions q1,q2] [--tag NAME] [split ...]

Default questions: the ones in policy-jev.json; default tag: jev_deployed. Output rows carry the
sha256 of the scored text. A rerun skips rows whose id and sha match and retries everything else,
including rows that changed and rows that failed. A row that cannot be scored is written as
{"id", "sha", "error"}: never as made-up scores.
"""
import argparse
import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from importlib.resources import files

from hermes_firewall.jev_detector import JevDetector

ap = argparse.ArgumentParser()
ap.add_argument("--questions", help="comma-separated; default: policy-jev.json")
ap.add_argument("--tag", default="jev_deployed")
ap.add_argument("splits", nargs="*", default=["test", "dev"])
args = ap.parse_args()
qs = args.questions.split(",") if args.questions else \
    json.loads(files("hermes_firewall").joinpath("policy-jev.json").read_text())["questions"]
det = JevDetector(os.environ["VENICE_API_KEY"], questions=qs, timeout=20, attempts=5, workers=2, max_wait=90)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_gate, _last = threading.Lock(), [0.0]
MIN_INTERVAL = 60 / 90  # stay under the key's 100 requests/minute; bursts over it cost a ~40 s wait


def score(r):
    with _gate:  # one request start per interval (a long page may still use several requests)
        time.sleep(max(0.0, _last[0] + MIN_INTERVAL - time.monotonic()))
        _last[0] = time.monotonic()
    try:
        return {"id": r["id"], "sha": sha(r["text"]), "text": det.score_many([r["text"]])[0]}
    except Exception as e:
        return {"id": r["id"], "sha": sha(r["text"]), "error": f"{type(e).__name__}: {e}"[:200]}


for split in args.splits:
    path = f"scores/{args.tag}_{split}.jsonl"
    rows = [json.loads(l) for l in open(f"corpus/{split}.extracted.jsonl")]
    want = {r["id"]: sha(r["text"]) for r in rows}
    kept = []
    if os.path.exists(path):  # keep only good rows that still match the corpus
        kept = [s for s in map(json.loads, open(path)) if "error" not in s and want.get(s["id"]) == s.get("sha")]
    done = {s["id"] for s in kept}
    todo = [r for r in rows if r["id"] not in done]
    with open(path, "w") as out:
        out.writelines(json.dumps(s) + "\n" for s in kept)
        out.flush()
        errors = 0
        with ThreadPoolExecutor(4) as ex:
            for n, res in enumerate(ex.map(score, todo), 1):
                errors += "error" in res
                out.write(json.dumps(res) + "\n")
                out.flush()
                if n % 100 == 0:
                    print(args.tag, split, n, "/", len(todo), "errors", errors, flush=True)
    print(args.tag, split, "scored", len(todo), "kept", len(kept), "errors", errors, flush=True)
