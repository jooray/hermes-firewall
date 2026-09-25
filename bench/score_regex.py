"""Naive baseline: the keyword list people usually start with."""
import json, re
PAT = re.compile(r"ignore (all |any )?(the )?(previous|prior|above|earlier)|disregard (all |the )?(previous|prior|above)|"
                 r"forget (all |everything|your|previous)|new instructions|system prompt|you are now|"
                 r"override|jailbreak|do anything now|developer mode|reveal (your|the) (prompt|instructions)", re.I)
for split in ("dev", "test"):
    with open(f"scores/regex_{split}.jsonl", "w") as out:
        for l in open(f"corpus/{split}.extracted.jsonl"):
            r = json.loads(l)
            out.write(json.dumps({"id": r["id"], **{f: {"p": float(bool(PAT.search(r[f]))), "ms": 0.0} for f in ("raw", "text")}}) + "\n")
