"""OCR engines compared end to end: extract every image with FIREWALL_OCR=<engine>, then score the
extracted text with Jev and apply the dev-fitted Jev policy. Usage: ocr_bench.py ENGINE [ENGINE...]"""
import json, os, statistics, sys, time
from pathlib import Path

for engine in sys.argv[1:]:
    os.environ["FIREWALL_OCR"] = engine
    import importlib, hermes_firewall.extract as X
    importlib.reload(X)
    for split in ("dev", "test"):
        out = open(f"corpus/ocr_{engine}_{split}.jsonl", "w")
        for l in open(f"corpus/{split}.jsonl"):
            r = json.loads(l)
            if r["kind"] != "image":
                continue
            data = Path("corpus", r["path"]).read_bytes()
            t = time.perf_counter(); e = X.extract(data); ms = (time.perf_counter() - t) * 1000
            out.write(json.dumps({"id": r["id"], "label": r["label"], "category": r["category"], "text": e.text,
                                  "flags": e.flags, "ms": ms}) + "\n")
        out.close()
    print(engine, "engine used:", X.ocr_engine(), flush=True)
