"""Baseline: protectai/deberta-v3-base-prompt-injection-v2 (max P(INJECTION) over 512-token chunks)."""
import json, os, time, torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

M = "protectai/deberta-v3-base-prompt-injection-v2"
tok = AutoTokenizer.from_pretrained(M)
model = AutoModelForSequenceClassification.from_pretrained(M).eval()
dev = "mps" if torch.backends.mps.is_available() else "cpu"
model.to(dev)
inj = [i for i, l in model.config.id2label.items() if l.upper().startswith("INJ")][0]

def score(text):
    ids = tok(text or " ", add_special_tokens=False)["input_ids"]
    chunks = [ids[i:i + 500] for i in range(0, max(1, len(ids)), 400)][:40] or [[]]
    batch = [[tok.cls_token_id] + c + [tok.sep_token_id] for c in chunks]
    L = max(map(len, batch))
    x = torch.tensor([b + [tok.pad_token_id] * (L - len(b)) for b in batch], device=dev)
    m = torch.tensor([[1] * len(b) + [0] * (L - len(b)) for b in batch], device=dev)
    with torch.no_grad():
        p = model(input_ids=x, attention_mask=m).logits.softmax(-1)[:, inj]
    return float(p.max())

score("warmup")
for split in ("dev", "test"):
    path = f"scores/deberta_{split}.jsonl"
    done = {json.loads(l)["id"] for l in open(path)} if os.path.exists(path) else set()
    with open(path, "a") as out:
        for l in open(f"corpus/{split}.extracted.jsonl"):
            r = json.loads(l)
            if r["id"] in done:
                continue
            res = {"id": r["id"]}
            for f in os.environ.get("FIELDS", "raw,text").split(","):
                t = time.perf_counter()
                res[f] = {"p": score(r[f]), "ms": (time.perf_counter() - t) * 1000}
            out.write(json.dumps(res) + "\n")
    print("deberta", split, "done", flush=True)
