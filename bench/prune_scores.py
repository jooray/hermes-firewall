"""Drop scores for rows whose extracted text changed (corpus/<split>.changed_v4.json), so the
resumable scorers rescore only those rows."""
import glob, json
for split in ("dev", "test"):
    ch = set(json.load(open(f"corpus/{split}.changed_v4.json")))
    for f in glob.glob(f"scores/*_{split}.jsonl"):
        rows = [l for l in open(f) if json.loads(l)["id"] not in ch]
        open(f, "w").writelines(rows)
        print(f, len(rows))
