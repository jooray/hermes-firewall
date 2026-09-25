"""Clean memory + latency per SemIf variant: MLX peak memory and p50 over 40 fixed test messages."""
import json, os, statistics, sys, time
sys.path.insert(0, "../firewall/src")
import mlx.core as mx
from hermes_firewall.semif_detector import SemIfDetector
bits = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1] != "bf16" else None
rows = [json.loads(l) for l in open("corpus/test.extracted.jsonl")]
msgs = [r["text"] for r in rows if r["source"] in ("bipia_email", "nostr", "deepset")][:40]
page = next(r["text"] for r in rows if r["source"] == "web_page")
det = SemIfDetector(bits=bits, questions=["override", "off_topic_task"])
det.score_many(["warm up"])
mx.reset_peak_memory()
lat = []
for m in msgs:
    t = time.perf_counter(); det.score_many([m]); lat.append((time.perf_counter() - t) * 1000)
t = time.perf_counter(); det.score_many([page]); page_ms = (time.perf_counter() - t) * 1000
print(json.dumps({"variant": sys.argv[1] if len(sys.argv) > 1 else "bf16", "weights_gb": round(mx.get_active_memory() / 1e9, 2),
                  "peak_gb": round(mx.get_peak_memory() / 1e9, 2), "msg_p50_ms": round(statistics.median(lat)),
                  "msg_p95_ms": round(sorted(lat)[int(.95 * (len(lat) - 1))]), "page_12k_ms": round(page_ms)}))
