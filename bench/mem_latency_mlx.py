"""Memory + latency of a local System One server outside Ollama (Decision-2.0-Lux-9B-MLX-4bit's
mlx_decision.py, or the benchmark's d1 shim), measured like mem_latency_ollama.py: p50/p95 over the same 40 test messages and
one ~12k-character web-page chunk. Memory: the server process's physical footprint and RSS, plus
whatever the server reports in /health (MLX peak, MPS allocation). Run it against a freshly started server for a clean peak.

    uv run python mem_latency_mlx.py URL [CHUNK_CHARS]

URL is the server's base, e.g. http://127.0.0.1:8047.
"""
import json
import re
import statistics
import subprocess
import sys
import time
import urllib.request

from hermes_firewall.jev_detector import JevDetector

API = sys.argv[1].rstrip("/")
chunk = int(sys.argv[2]) if len(sys.argv) > 2 else 12000
qs = ["off_topic_task", "choice_kind"]
det = JevDetector("local", model="jev-latest", questions=qs, url=API + "/v1/systemone", timeout=300, workers=1,
                 chunk_chars=chunk, overlap=min(400, chunk // 10))
rows = [json.loads(l) for l in open("corpus/test.extracted.jsonl")]
msgs = [r["text"] for r in rows if r["source"] in ("bipia_email", "nostr", "deepset")][:40]
page = next(r["text"] for r in rows if r["source"] == "web_page" and len(r["text"]) >= 12000)[:12000]
det.score_many(["warm up"])
lat = []
for m in msgs:
    t = time.perf_counter()
    det.score_many([m])
    lat.append((time.perf_counter() - t) * 1000)
t = time.perf_counter()
det.score_many([page])
page_ms = (time.perf_counter() - t) * 1000

health = json.load(urllib.request.urlopen(API + "/health"))
port = API.rsplit(":", 1)[1]
pid = subprocess.run(["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True).stdout.split()[0]
out = subprocess.run(["footprint", "--pid", pid], capture_output=True, text=True).stdout
m = re.search(r"Footprint:\s*([\d.]+)\s*([KMG])B", out)
footprint = m and float(m.group(1)) * {"K": 1e-6, "M": 1e-3, "G": 1}[m.group(2)]
rss = int(subprocess.run(["ps", "-o", "rss=", "-p", pid], capture_output=True, text=True).stdout) / 1e6
print(json.dumps({"model": (health.get("model") or "rsi-jev").rsplit("/", 1)[-1], "chunk_chars": chunk, **{k: v for k, v in health.items() if k.endswith("_gb")},
                  "server_footprint_gb": footprint and round(footprint, 2), "server_rss_gb": round(rss, 2),
                  "msg_p50_ms": round(statistics.median(lat)), "msg_p95_ms": round(sorted(lat)[int(.95 * (len(lat) - 1))]),
                  "page_12k_ms": round(page_ms)}))
