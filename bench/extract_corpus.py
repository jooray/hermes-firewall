"""Run the firewall's extraction over the corpus; write *.extracted.jsonl."""
import json, sys, time
from pathlib import Path
from hermes_firewall.extract import extract

for split in sys.argv[1:] or ["dev", "test"]:
    with open(f"corpus/{split}.extracted.jsonl", "w") as out:
        for line in open(f"corpus/{split}.jsonl"):
            r = json.loads(line)
            t = time.perf_counter()
            if r["kind"] == "image":
                e = extract(Path("corpus", r["path"]).read_bytes())
                raw = ""  # a text-only scanner sees nothing in an image
            else:
                e = extract(r["text"])
                raw = r["text"]
            r.update(raw=raw, text=e.text, flags=e.flags, extract_ms=(time.perf_counter() - t) * 1000)
            out.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(split, "done")
