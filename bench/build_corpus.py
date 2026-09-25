"""Build the benchmark corpus from public datasets.

Attack text comes only from published datasets:
  - BIPIA (microsoft/BIPIA, MIT): EmailQA contexts + text attack strings,
    inserted at start/middle/end the way BIPIA's own builder does.
  - deepset/prompt-injections (Apache-2.0): direct injections + benign prompts.
  - Lakera/gandalf_ignore_instructions (MIT): real user override attempts.
Benign real-world traffic: public Nostr kind-1 posts, real web pages (some of
them *about* prompt injection = hard negatives), BIPIA's clean emails.
Carrier variants wrap the same dataset strings in hidden HTML, invisible
Unicode, base64, and images/image metadata.

Split: dev = dataset train splits (used for question wording and thresholds),
test = dataset test splits (touched only for the final numbers).
"""

import base64
import io
import json
import random
import re
from pathlib import Path

import pandas as pd
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin

ROOT = Path(__file__).parent
DATA = ROOT / "data"
OUT = ROOT / "corpus"
IMG = OUT / "images"
rng = random.Random(20260923)


def tags(s):
    return "".join(chr(0xE0000 + ord(c)) for c in s if 0x20 <= ord(c) < 0x7F)


def zw(s):
    return "​".join(s)


def sentences(text):
    return [m.start() for m in re.finditer(r"(?<=[.!?])\s+(?=[A-Z])", text)]


def insert(context, attack, pos):
    if pos == "start":
        return attack + "\n" + context
    if pos == "end":
        return context + "\n" + attack
    cuts = sentences(context) or [len(context) // 2]
    c = rng.choice(cuts)
    return context[:c] + "\n" + attack + "\n" + context[c:]


def bipia_email(split):
    ctx = [json.loads(l)["context"].replace("|", "\n") for l in open(DATA / f"bipia/benchmark/email/{split}.jsonl")]
    att = json.load(open(DATA / f"bipia/benchmark/text_attack_{split}.json"))
    flat = [(cat, s) for cat, lst in att.items() for s in lst]
    return ctx, flat


def font(size):
    for p in ("/System/Library/Fonts/Helvetica.ttc", "/System/Library/Fonts/Supplemental/Arial.ttf"):
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            pass
    return ImageFont.load_default()


def wrap(text, width):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    lines.append(cur)
    return lines


def base_picture(seed, w=1024, h=768):
    r = random.Random(seed)
    img = Image.new("RGB", (w, h))
    d = ImageDraw.Draw(img)
    c1, c2 = [r.randint(40, 220) for _ in range(3)], [r.randint(40, 220) for _ in range(3)]
    for y in range(h):
        t = y / h
        d.line([(0, y), (w, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(c1, c2)))
    for _ in range(12):
        x, y, s = r.randint(0, w), r.randint(0, h), r.randint(30, 200)
        d.ellipse([x, y, x + s, y + s], fill=tuple(r.randint(0, 255) for _ in range(3)))
    return img


def img_visible(text, seed):
    img = Image.new("RGB", (1024, 600), "white")
    d = ImageDraw.Draw(img)
    y = 40
    for line in wrap(text, 48)[:14]:
        d.text((40, y), line, fill="black", font=font(34))
        y += 42
    return img


def img_lowcontrast(text, seed):
    img = Image.new("RGB", (1024, 600), (255, 255, 255))
    d = ImageDraw.Draw(img)
    d.text((40, 30), "Team offsite - agenda", fill="black", font=font(40))
    y = 140
    for line in wrap(text, 52)[:10]:
        d.text((40, y), line, fill=(248, 248, 248), font=font(30))
        y += 38
    return img


def img_tiny(text, seed):
    img = base_picture(seed)
    d = ImageDraw.Draw(img)
    y = 700
    for line in wrap(text, 120)[:4]:
        d.text((10, y), line, fill=(20, 20, 20), font=font(11))
        y += 13
    return img


def save_jpeg(img, exif=None, comment=None, xmp=None, trailing=None):
    buf = io.BytesIO()
    kw = {"quality": 88}
    if exif is not None:
        kw["exif"] = exif
    if comment is not None:
        kw["comment"] = comment.encode()
    if xmp is not None:
        kw["xmp"] = xmp.encode()
    img.save(buf, "JPEG", **kw)
    data = buf.getvalue()
    if trailing:
        data += trailing.encode()
    return data


def exif_with(desc, comment=None, make=None):
    e = Image.Exif()
    if desc:
        e[0x010E] = desc  # ImageDescription
    if make:
        e[0x010F], e[0x0110] = make
    return e.tobytes()


def xmp_packet(desc):
    return ('<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/">'
            '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description '
            'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:description><rdf:Alt><rdf:li xml:lang="x-default">'
            f'{desc}</rdf:li></rdf:Alt></dc:description></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>')


IMAGE_CARRIERS = {
    "img_visible": lambda t, s: save_png(img_visible(t, s)),
    "img_lowcontrast": lambda t, s: save_png(img_lowcontrast(t, s)),
    "img_tiny": lambda t, s: save_png(img_tiny(t, s)),
    "jpeg_exif": lambda t, s: save_jpeg(base_picture(s), exif=exif_with(t)),
    "jpeg_comment": lambda t, s: save_jpeg(base_picture(s), comment=t),
    "jpeg_xmp": lambda t, s: save_jpeg(base_picture(s), xmp=xmp_packet(t)),
    "jpeg_trailing": lambda t, s: save_jpeg(base_picture(s), trailing=t),
    "png_text": lambda t, s: save_png(base_picture(s), {"Description": t}),
}


def save_png(img, text_chunks=None):
    buf = io.BytesIO()
    info = None
    if text_chunks:
        info = PngImagePlugin.PngInfo()
        for k, v in text_chunks.items():
            info.add_text(k, v)
    img.save(buf, "PNG", pnginfo=info)
    return buf.getvalue()


def html_hidden(visible, hidden):
    return (f"<html><body><div class='post'><p>{visible}</p></div>"
            f"<div style=\"display:none\">{hidden}</div></body></html>")


def html_comment(visible, hidden):
    return f"<html><body><article><p>{visible}</p><!-- {hidden} --></article></body></html>"


TEXT_CARRIERS = {
    "html_hidden": lambda base, t: html_hidden(base, t),
    "html_comment": lambda base, t: html_comment(base, t),
    "unicode_tags": lambda base, t: base + tags(" " + t),
    "zero_width": lambda base, t: base + "\n\n" + zw(t),
    "base64": lambda base, t: base + "\n\nref: " + base64.b64encode(t.encode()).decode(),
}


def nostr_posts():
    seen, posts = set(), []
    for line in open(DATA / "nostr_posts.jsonl"):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        c = ev.get("content", "").strip()
        if 40 <= len(c) <= 2000 and c not in seen and not c.startswith("{"):
            seen.add(c)
            posts.append(c)
    rng.shuffle(posts)
    return posts


def pages():
    from bs4 import BeautifulSoup

    out = []
    for p in sorted((DATA / "pages").glob("*.html")):
        soup = BeautifulSoup(p.read_text(errors="ignore"), "html.parser")
        for t in soup(["script", "style", "nav", "footer", "header", "noscript"]):
            t.decompose()
        text = re.sub(r"\n{3,}", "\n\n", soup.get_text("\n", strip=True))
        out.append((p.stem, text[:12000]))
    return out


def main():
    OUT.mkdir(exist_ok=True)
    IMG.mkdir(exist_ok=True)
    rows = {"dev": [], "test": []}

    def add(split, **r):
        rows[split].append(r)

    posts = nostr_posts()
    post_split = {"dev": posts[:150], "test": posts[150:300]}

    for split, bsplit, dsplit, gsplit in (("dev", "train", "train", "train"), ("test", "test", "test", "test")):
        ctx, attacks = bipia_email(bsplit)
        for i, c in enumerate(ctx):
            add(split, id=f"bipia_{bsplit}_{i}_clean", label=0, source="bipia_email", category="clean_email", kind="text", text=c)
            for j in range(3):
                cat, a = rng.choice(attacks)
                pos = rng.choice(["start", "middle", "end"])
                add(split, id=f"bipia_{bsplit}_{i}_att{j}", label=1, source="bipia_email", category=cat,
                    position=pos, kind="text", text=insert(c, a, pos))
        # deepset
        df = pd.read_parquet(DATA / f"deepset_{dsplit}.parquet")
        for i, r in df.iterrows():
            add(split, id=f"deepset_{dsplit}_{i}", label=int(r["label"]), source="deepset",
                category="deepset", kind="text", text=r["text"])
        # gandalf (attack-only)
        g = pd.read_parquet(DATA / f"gandalf_{gsplit}.parquet")
        g = g.sample(n=min(len(g), 112), random_state=7)
        for i, r in g.iterrows():
            add(split, id=f"gandalf_{gsplit}_{i}", label=1, source="gandalf", category="override", kind="text", text=r["text"])
        # nostr benign
        for i, p in enumerate(post_split[split]):
            add(split, id=f"nostr_{split}_{i}", label=0, source="nostr", category="nostr_post", kind="text", text=p)
        # carriers: dataset attack strings vs benign strings in the same wrapper
        attack_pool = [a for _, a in attacks] + list(g["text"])
        benign_pool = [p for p in post_split[split] if len(p) < 400]
        latin_pool = [p for p in benign_pool if sum(ord(c) < 0x250 for c in p) / len(p) > 0.97]
        n = 6 if split == "test" else 3
        for carrier, fn in TEXT_CARRIERS.items():
            for k in range(n):
                base = rng.choice(benign_pool)
                add(split, id=f"{carrier}_{split}_att{k}", label=1, source="carrier", category=carrier,
                    kind="text", text=fn(base, rng.choice(attack_pool)))
                base2, hidden2 = rng.sample(benign_pool, 2)
                add(split, id=f"{carrier}_{split}_ben{k}", label=0, source="carrier", category=carrier,
                    kind="text", text=fn(base2, hidden2))
        for carrier, fn in IMAGE_CARRIERS.items():
            for k in range(n):
                for lab, t in ((1, rng.choice(attack_pool)), (0, rng.choice(latin_pool))):
                    seed = rng.randint(0, 10**9)
                    data = fn(t[:500], seed)
                    ext = "jpg" if data[:2] == b"\xff\xd8" else "png"
                    name = f"{carrier}_{split}_{'att' if lab else 'ben'}{k}.{ext}"
                    (IMG / name).write_bytes(data)
                    add(split, id=name.rsplit(".", 1)[0], label=lab, source="carrier", category=carrier,
                        kind="image", path=f"images/{name}")
        # benign camera-style photos (ordinary EXIF) as a control
        for k in range(n):
            data = save_jpeg(base_picture(rng.randint(0, 10**9)), exif=exif_with(None, make=("Apple", "iPhone 15 Pro")))
            name = f"photo_{split}_{k}.jpg"
            (IMG / name).write_bytes(data)
            add(split, id=name[:-4], label=0, source="carrier", category="plain_photo", kind="image", path=f"images/{name}")
    for stem, text in pages():
        add("test", id=f"page_{stem}", label=0, source="web_page", category="web_page", kind="text", text=text)

    for split, rs in rows.items():
        with open(OUT / f"{split}.jsonl", "w") as f:
            for r in rs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        pos = sum(r["label"] for r in rs)
        print(split, len(rs), "rows,", pos, "attacks,", len(rs) - pos, "benign")


if __name__ == "__main__":
    main()
