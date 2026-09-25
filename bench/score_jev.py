"""Jev (TypeSafe System One) via Venice /api/v1/decisions, same 7 questions as Laya, extracted text.
Resumable; 4 concurrent requests. Needs VENICE_API_KEY."""
import json, os, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "../firewall/src")
from hermes_firewall.laya_detector import QUESTIONS

URL = "https://api.venice.ai/api/v1/decisions"
KEY = os.environ["VENICE_API_KEY"]
MAX_CHARS = 90_000  # state limit is 32k tokens

def p_yes(ans):
    if ans["type"] == "noul":
        return float(ans["noul"])
    if ans["type"] == "choice":
        return float(ans["probabilities"].get("injection", 0.0))
    pr = ans["probabilities"]
    return float(pr[str(max(int(k) for k in pr))])

def call(text):
    res = call_one(text)
    if res == "server_error" and len(text) > 3000:
        # Jev answers HTTP 500 "Inference processing failed" on some long pages; fall back to
        # 3k-char chunks and take the max per question, as a production client would.
        from hermes_firewall.laya_detector import chunk_text
        parts = [call_one(c) for c in chunk_text(text, 3000, 200)]
        if all(isinstance(p, dict) for p in parts):
            return {q: max(p[q] for p in parts) for q in QUESTIONS} | {
                "ms": sum(p["ms"] for p in parts), "tokens": sum(p["tokens"] for p in parts), "chunked": len(parts)}
        return None
    return res if isinstance(res, dict) else None

def call_one(text):
    if not text.strip():
        return dict.fromkeys(QUESTIONS, 0.0) | {"ms": 0.0, "tokens": 0}
    body = json.dumps({"model": "jev-latest", "state": text[:MAX_CHARS], "questions": QUESTIONS}).encode()
    for attempt in range(8):
        req = urllib.request.Request(URL, data=body, headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
        t = time.perf_counter()
        try:
            r = json.load(urllib.request.urlopen(req, timeout=120))
            out = {q: p_yes(a) for q, a in r["answers"].items()}
            return out | {"ms": (time.perf_counter() - t) * 1000, "tokens": r["usage"]["input_tokens"]}
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(min(60, 2 ** attempt)); continue
            raise RuntimeError(f"{e.code} {e.read()[:200]}")
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(min(60, 2 ** attempt))
    return "server_error"  # caller chunks or leaves it out; a rerun retries it

for split in sys.argv[1:] or ["test", "dev"]:
    path = f"scores/jev_{split}.jsonl"
    done = {json.loads(l)["id"] for l in open(path)} if os.path.exists(path) else set()
    rows = [json.loads(l) for l in open(f"corpus/{split}.extracted.jsonl")]
    rows = [r for r in rows if r["id"] not in done]
    failed = 0
    with open(path, "a") as out, ThreadPoolExecutor(4) as ex:
        for r, res in zip(rows, ex.map(lambda r: call(r["text"]), rows)):
            if res is None:
                failed += 1; continue
            out.write(json.dumps({"id": r["id"], "text": res}) + "\n"); out.flush()
    print("jev", split, "failed", failed, flush=True)
    print("jev", split, "done", flush=True)
