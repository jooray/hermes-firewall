"""Score raw and extracted text with Laya. Usage: score_laya.py MODEL_ID TAG"""
import json, os, sys, time
from hermes_firewall.laya_detector import LayaDetector

model, tag = sys.argv[1], sys.argv[2]
det = LayaDetector(model)
det.score_many(["warmup text"])
for split in ("dev", "test"):
    rows = [json.loads(l) for l in open(f"corpus/{split}.extracted.jsonl")]
    path = f"scores/{tag}_{split}.jsonl"
    done = {json.loads(l)["id"] for l in open(path)} if os.path.exists(path) else set()
    with open(path, "a") as out:
        for r in rows:
            if r["id"] in done:
                continue
            res = {"id": r["id"]}
            for field in os.environ.get("FIELDS", "raw,text").split(","):
                t = time.perf_counter()
                s = det.score_many([r[field]])[0]
                s["ms"] = (time.perf_counter() - t) * 1000
                res[field] = s
            out.write(json.dumps(res) + "\n")
    print(tag, split, "done", flush=True)
