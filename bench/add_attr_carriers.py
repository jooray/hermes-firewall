"""Append attribute/markup carriers (v4) to corpus/{dev,test}.jsonl without touching existing rows.

Dataset attack strings (deepset + Gandalf of the same split) or benign Nostr posts are placed where a
rendered page never shows them, but a model reading raw HTML does: id, data-*, <meta content>,
<script> string, JSON-LD, img alt. Each attack row has a benign twin in the same carrier.
Idempotent: previous attr_* rows are replaced."""
import html, json, random

def esc(s): return html.escape(s, quote=True)
def page(visible, head="", body=""):
    return f"<html><head><title>Notes</title>{head}</head><body>{body}<article><p>{esc(visible)}</p></article></body></html>"

CARRIERS = {
    "attr_id": lambda v, t: page(v, body=f'<div id="{esc(t)}"></div>'),
    "attr_data": lambda v, t: page(v, body=f'<section data-note="{esc(t)}"></section>'),
    "attr_meta": lambda v, t: page(v, head=f'<meta name="description" content="{esc(t)}">'),
    "attr_script": lambda v, t: page(v, body="<script>var cfg = " + json.dumps({"msg": t}) + ";</script>"),
    "attr_jsonld": lambda v, t: page(v, head='<script type="application/ld+json">' + json.dumps({"@type": "Article", "description": t}) + "</script>"),
    "attr_alt": lambda v, t: page(v, body=f'<img src="banner.png" alt="{esc(t)}">'),
}

for split in ("dev", "test"):
    path = f"corpus/{split}.jsonl"
    rows = [r for r in map(json.loads, open(path)) if not r["category"].startswith("attr_")]
    rng = random.Random(f"attr-carriers-{split}")
    attacks = [r["text"] for r in rows if r["label"] == 1 and r["source"] in ("deepset", "gandalf") and 8 < len(r["text"]) < 500]
    benign = [r["text"] for r in rows if r["source"] == "nostr" and len(r["text"]) < 400]
    n = 6 if split == "test" else 3
    for c, fn in CARRIERS.items():
        for k in range(n):
            rows.append({"id": f"{c}_{split}_att{k}", "label": 1, "source": "carrier", "category": c, "kind": "text",
                         "text": fn(rng.choice(benign), rng.choice(attacks))})
            v, h = rng.sample(benign, 2)
            rows.append({"id": f"{c}_{split}_ben{k}", "label": 0, "source": "carrier", "category": c, "kind": "text",
                         "text": fn(v, h)})
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(split, len(rows), "rows", sum(r["label"] for r in rows), "attacks")
