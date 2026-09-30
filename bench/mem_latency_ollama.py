"""Memory + latency of a local System One model under Ollama, measured like mem_latency.py:
p50/p95 over 40 fixed test messages and one ~12k-character web-page chunk, with the model
loaded fresh (other models unloaded first). Memory: Ollama's own allocation (`/api/ps` size,
weights + KV cache + compute buffers), the llama-server runner's physical footprint (dirty
memory) and its RSS (which also counts mapped weight-file pages).

    uv run python mem_latency_ollama.py MODEL [CHUNK_CHARS]

CHUNK_CHARS as used for scoring (score_ollama.py --chunk-chars; 12000 default, 3000 for Tev1).
"""
import json
import re
import statistics
import subprocess
import sys
import time
import urllib.request

from hermes_firewall.jev_detector import JevDetector

model = sys.argv[1]
API = "http://127.0.0.1:11434"


def ps():
    return json.load(urllib.request.urlopen(API + "/api/ps"))["models"]


for m in ps():  # unload everything so the numbers are this model's alone
    body = json.dumps({"model": m["name"], "keep_alive": 0}).encode()
    urllib.request.urlopen(urllib.request.Request(API + "/api/generate", data=body, headers={"Content-Type": "application/json"}))
while ps():
    time.sleep(0.5)

qs = ["off_topic_task", "choice_kind"]
chunk = int(sys.argv[2]) if len(sys.argv) > 2 else 12000
det = JevDetector("local", model=model, questions=qs, url=API + "/v1/systemone", timeout=300, workers=1,
                 chunk_chars=chunk, overlap=min(400, chunk // 10))
rows = [json.loads(l) for l in open("corpus/test.extracted.jsonl")]
msgs = [r["text"] for r in rows if r["source"] in ("bipia_email", "nostr", "deepset")][:40]
page = next(r["text"] for r in rows if r["source"] == "web_page" and len(r["text"]) >= 12000)[:12000]
t = time.perf_counter()
det.score_many(["warm up"])
load_ms = (time.perf_counter() - t) * 1000
lat = []
for m in msgs:
    t = time.perf_counter()
    det.score_many([m])
    lat.append((time.perf_counter() - t) * 1000)
t = time.perf_counter()
det.score_many([page])
page_ms = (time.perf_counter() - t) * 1000

info = next(m for m in ps() if m["name"].startswith(model.split(":")[0]))
footprint = rss = None
pids = subprocess.run(["pgrep", "-f", "llama-server"], capture_output=True, text=True).stdout.split()
if len(pids) == 1:  # everything else was unloaded above, so this runner holds this model
    out = subprocess.run(["footprint", "--pid", pids[0]], capture_output=True, text=True).stdout
    m = re.search(r"Footprint:\s*([\d.]+)\s*([KMG])B", out)
    footprint = m and float(m.group(1)) * {"K": 1e-6, "M": 1e-3, "G": 1}[m.group(2)]
    rss = int(subprocess.run(["ps", "-o", "rss=", "-p", pids[0]], capture_output=True, text=True).stdout) / 1e6
print(json.dumps({"model": model, "chunk_chars": chunk, "ollama_size_gb": round(info["size"] / 1e9, 2),
                  "ollama_vram_gb": round(info.get("size_vram", 0) / 1e9, 2),
                  "context": info.get("context_length"), "runner_footprint_gb": footprint and round(footprint, 2), "runner_rss_gb": rss and round(rss, 2),
                  "cold_load_ms": round(load_ms), "msg_p50_ms": round(statistics.median(lat)),
                  "msg_p95_ms": round(sorted(lat)[int(.95 * (len(lat) - 1))]), "page_12k_ms": round(page_ms)}))
