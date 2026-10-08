"""Image carriers scored by a multimodal System One model with the picture itself instead of OCR.

The state is the item's extracted text with the OCR lines ("[image text]", "[small image text]",
"[faint image text]") removed, so metadata the extractor reads (EXIF, XMP, JPEG comment, trailing
bytes, PNG text) is still there, and the image goes in as pixels (`image_paths`, understood by the
benchmark's d1 shim server, not by Jev or Ollama). An item with no text left has state None. Same
two questions as the deployed Jev backend, one request per image, no chunking (the remaining text
is short).

    uv run python score_d1_images.py URL TAG [split ...]

Writes scores/{TAG}_img_{split}.jsonl with the same row format as score_ollama.py, image items only.
"""
import hashlib
import json
import os
import sys
import time
import urllib.request
from importlib.resources import files

from hermes_firewall.jev_detector import QUESTIONS, p_yes

url, tag = sys.argv[1], sys.argv[2]
splits = sys.argv[3:] or ["test", "dev"]
qs = json.loads(files("hermes_firewall").joinpath("policy-jev.json").read_text())["questions"]
questions = {q: QUESTIONS[q] for q in qs}
OCR = ("[image text]:", "[small image text]:", "[faint image text]:")


def state_of(text):
    # an OCR block can span lines; drop continuation lines until the next "[...]:" header
    out, skipping = [], False
    for l in text.split("\n"):
        if l.startswith(OCR):
            skipping = True
        elif l.startswith("[") and "]: " in l[:40]:
            skipping = False
        if not skipping:
            out.append(l)
    s = "\n".join(out).strip()
    return s or None


for split in splits:
    rows = [json.loads(l) for l in open(f"corpus/{split}.extracted.jsonl")]
    rows = [r for r in rows if r.get("kind") == "image"]
    path = f"scores/{tag}_img_{split}.jsonl"
    with open(path, "w") as out:
        for r in rows:
            state = state_of(r["text"])
            body = json.dumps({"state": state, "questions": questions,
                               "image_paths": [os.path.abspath("corpus/" + r["path"])]}).encode()
            sha = hashlib.sha256((r["text"] + r["path"]).encode()).hexdigest()
            t = time.perf_counter()
            try:
                req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
                res = json.load(urllib.request.urlopen(req, timeout=300))
                s = {q: p_yes(a) for q, a in res["answers"].items()}
                row = {"id": r["id"], "sha": sha, "text": s | {"n_chunks": 1, "tokens": res.get("usage", {}).get("input_tokens", 0),
                                                              "ms": (time.perf_counter() - t) * 1000, "state_chars": len(state or "")}}
            except Exception as e:
                row = {"id": r["id"], "sha": sha, "error": f"{type(e).__name__}: {e}"[:200]}
            out.write(json.dumps(row) + "\n")
    print(tag, split, "image items", len(rows), flush=True)
