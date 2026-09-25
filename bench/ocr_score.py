"""Score ocr_<engine>_<split>.jsonl with Jev (resumable) and report detection per image carrier."""
import json, os, sys, statistics
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "../firewall/src")
from hermes_firewall.jev_detector import JevDetector
from hermes_firewall.policy import Policy
from sklearn.metrics import roc_auc_score

pol = Policy(**json.load(open("../firewall/src/hermes_firewall/policy-jev.json")))
jev = JevDetector(os.environ["VENICE_API_KEY"], questions=pol.questions, attempts=6, workers=1, max_wait=65)
PIXEL = {"img_visible", "img_lowcontrast", "img_tiny"}
for engine in sys.argv[1:]:
    res = {}
    for split in ("test",):
        rows = [json.loads(l) for l in open(f"corpus/ocr_{engine}_{split}.jsonl")]
        cache = f"scores/jev_ocr_{engine}_{split}.jsonl"
        done = {json.loads(l)["id"]: json.loads(l) for l in open(cache)} if os.path.exists(cache) else {}
        todo = [r for r in rows if r["id"] not in done]
        with ThreadPoolExecutor(2) as ex, open(cache, "a") as f:
            for r, s in zip(todo, ex.map(lambda r: jev.score_many([r["text"]])[0], todo)):
                done[r["id"]] = {"id": r["id"], **s}; f.write(json.dumps(done[r["id"]]) + "\n")
        per = defaultdict(lambda: defaultdict(int)); y, v = [], []
        for r in rows:
            d = pol.decide(done[r["id"]], r["flags"]) if r["text"].strip() else pol.decide({}, r["flags"])
            grp = "pixel" if r["category"] in PIXEL else "photo" if r["category"] == "plain_photo" else "metadata"
            per[(grp, r["label"])][d["verdict"]] += 1
            if grp == "pixel":
                y.append(r["label"]); v.append(pol.score(done[r["id"]]))
        ms = sorted(r["ms"] for r in rows)
        print(f"== {engine}: pixel-text AUC {roc_auc_score(y, v):.3f} | extract median {statistics.median(ms)/1000:.1f}s p95 {ms[int(.95*(len(ms)-1))]/1000:.1f}s")
        for k in sorted(per):
            n = sum(per[k].values()); c = per[k]
            print(f"   {k[0]:8s} {'attack' if k[1] else 'benign':6s} n={n:2d} block {c['injection']:2d} warn {c['suspicious']:2d} pass {c['safe']:2d}")
