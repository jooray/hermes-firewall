"""Turn untrusted input into the text a detector should see.

The detector must see everything the agent's model could see, including what a
human would not: invisible Unicode, hidden HTML, encoded blobs, text inside
images and image metadata. Each reveal also raises a structural flag, because
hiding text from humans is itself a signal.
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser

TAG_LO, TAG_HI = 0xE0000, 0xE007F
ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u180e"}  # written as escapes: never put invisible characters in source
BIDI = {chr(c) for c in range(0x202A, 0x202F)} | {chr(c) for c in range(0x2066, 0x206A)}
B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.\d+)?(?:px|em|pt)?\b"
    r"|opacity\s*:\s*0(?:\.0+)?\b|color\s*:\s*(?:#fff(?:fff)?|white|transparent)\b"
    r"|(?:left|top)\s*:\s*-\d{3,}px|height\s*:\s*0|width\s*:\s*0", re.I)


@dataclass
class Extracted:
    text: str                                  # what the detector scores
    flags: list[str] = field(default_factory=list)
    revealed: list[str] = field(default_factory=list)  # hidden fragments, for the report


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(ch.isprintable() or ch in "\n\r\t" for ch in s)
    return ok / len(s)


def reveal_unicode(text: str, out: Extracted) -> str:
    tags = "".join(chr(ord(c) - TAG_LO) for c in text if TAG_LO <= ord(c) <= TAG_HI)
    tags = "".join(c for c in tags if c.isprintable())
    if tags.strip():
        out.flags.append("unicode_tags")
        out.revealed.append(tags)
    zw = sum(c in ZERO_WIDTH for c in text)
    if zw >= 8:
        out.flags.append("zero_width")
    if any(c in BIDI for c in text):
        out.flags.append("bidi_override")
    clean = "".join(c for c in text if not (TAG_LO <= ord(c) <= TAG_HI) and c not in ZERO_WIDTH and c not in BIDI)
    clean = unicodedata.normalize("NFKC", clean)
    if tags.strip():
        clean += "\n[hidden unicode-tag text]: " + tags
    return clean


def reveal_base64(text: str, out: Extracted) -> str:
    extra = []
    for m in B64_RUN.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            dec = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(dec) >= 12 and _printable_ratio(dec) > 0.95 and re.search(r"[A-Za-z]{3,}\s+[A-Za-z]{2,}", dec):
            extra.append(dec)
    if extra:
        out.flags.append("base64_text")
        out.revealed.extend(extra)
        text += "".join(f"\n[decoded base64]: {d}" for d in extra)
    return text


OPAQUE = re.compile(r"(?:nostr:)?[A-Za-z0-9_\-+/=]{32,}")


def collapse_opaque(text: str) -> str:
    """Replace long opaque tokens (hex ids, bech32 nostr refs, base64 blobs, API tokens) with a
    placeholder. They carry no instructions (decodable base64 was already revealed) and the
    classifier reads long random strings as suspicious: 23 of 29 dev false positives at warn
    level contained one."""
    return OPAQUE.sub(lambda m: f"[id:{len(m.group(0))}]", text)


def looks_like_html(text: str) -> bool:
    return bool(re.search(r"<(html|body|div|p|span|table|a |img |!--)", text[:5000], re.I))


# The scanner must see at least what the agent's model can see. A model reading raw HTML
# (curl, raw fetches) reads every attribute and script, so extraction only ever ADDS text:
# visible text, then everything a human would not see.
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr"}
RAW_TEXT = {"script", "style", "noscript", "template", "textarea"}
A11Y_ATTRS = {"alt", "title", "aria-label", "aria-description", "placeholder", "label", "summary"}
# id values cannot legally contain spaces, so a sentence in an id is a deliberate plant. Real
# sites put UI strings in data-* and word lists in class, so those are scored but not flagged.
FLAG_ATTRS = {"id"}
BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article",
         "header", "footer", "td", "th", "pre", "blockquote", "ul", "ol", "table", "hr"}
STRING_LITERAL = re.compile(r'"((?:[^"\\\n]|\\.){12,})"|\'((?:[^\'\\\n]|\\.){12,})\'|`([^`]{12,})`')


def natural_language(value: str, min_words: int = 3) -> bool:
    """Sentence-like text, not class lists, URLs, ids or code: enough plain words."""
    toks = value.split()
    words = [t for t in toks if re.fullmatch(r"[^\W\d_][^\W\d_'’.,:;!?()-]*[.,:;!?)]?", t)]
    return len(words) >= min_words and len(words) >= 0.5 * len(toks)


class _HTMLCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.visible, self.hidden, self.a11y, self.meta, self.attr_text, self.code = [], [], [], [], [], []
        self.stack = []          # (tag, is_hidden) for non-void open tags
        self.raw = None          # inside script/style/...
        self.never_shown_hits = 0

    def _hidden_now(self):
        return any(h for _, h in self.stack)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        is_hidden = ("hidden" in a or a.get("aria-hidden") == "true" or bool(HIDDEN_STYLE.search(a.get("style", "")))
                     or (tag == "input" and a.get("type", "").lower() == "hidden"))
        for k, v in a.items():
            v = v.strip()
            if not v:
                continue
            if k in A11Y_ATTRS:
                self.a11y.append(v)
            elif tag == "meta" and k == "content" and natural_language(v, 2):
                self.meta.append(v)
            elif natural_language(v):
                self.attr_text.append(f"{k}: {v}")
                if k in FLAG_ATTRS and natural_language(v, 4):
                    self.never_shown_hits += 1
        if tag in BLOCK:
            (self.hidden if self._hidden_now() or is_hidden else self.visible).append("\n")
        if tag in RAW_TEXT:
            self.raw = tag
        if tag not in VOID:
            self.stack.append((tag, is_hidden))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        if tag == self.raw:
            self.raw = None
        for i in range(len(self.stack) - 1, -1, -1):  # tolerate unclosed tags
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self.raw:
            if self.raw in ("noscript", "template", "textarea"):
                self.code.append(data)
            else:
                self.code.extend(m.group(1) or m.group(2) or m.group(3) for m in STRING_LITERAL.finditer(data))
            return
        (self.hidden if self._hidden_now() else self.visible).append(data)

    def handle_comment(self, data):
        if data.strip():
            self.hidden.append(data.strip())


def _norm(chunks):
    text = "".join(chunks)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    return re.sub(r"\s*\n\s*", "\n", text).strip()


def html_to_text(html: str, out: Extracted) -> str:
    c = _HTMLCollector()
    c.feed(html)
    c.close()
    hidden = _norm(" ".join(c.hidden) if c.hidden else "")
    code = [s for s in dict.fromkeys(x.strip() for x in c.code) if natural_language(s)]
    code_text = " | ".join(code)  # never truncated: an attacker could pad ahead of the payload
    if len(hidden.split()) >= 6:
        out.flags.append("html_hidden_text")
        out.revealed.append(hidden)
    if c.never_shown_hits:
        out.flags.append("html_attribute_text")
        out.revealed.extend(c.attr_text[:5])
    visible = _norm(c.visible)
    seen = visible.lower()
    # alt/title text that repeats visible text adds nothing (Wikipedia link titles: ~70k chars)
    a11y = [x for x in c.a11y if x.lower() not in seen]
    parts = [visible]
    for label, items in (("accessibility text", a11y), ("meta", c.meta), ("html attribute text", c.attr_text)):
        items = list(dict.fromkeys(items))
        if items:
            parts.append(f"[{label}]: " + " | ".join(items))
    if code_text:
        parts.append("[script/style text]: " + code_text)
    if hidden:
        parts.append("[hidden html content]: " + hidden)
    return "\n".join(p for p in parts if p)


# ------------------------------------------------------------------ images --

# OCR engines, tried in order by FIREWALL_OCR=auto (or pin one: apple | tesseract | rapidocr | none).
# apple: macOS Vision via ocrmac. tesseract: the `tesseract` CLI (one system package on any OS).
# rapidocr: PaddleOCR models on onnxruntime, used only if the rapidocr_onnxruntime package is present.
# Each engine returns a list of text lines.
OCR_TIMEOUT = 20


def _ocr_apple(img):
    from ocrmac import ocrmac
    return [r[0] for r in ocrmac.OCR(img, recognition_level="accurate").recognize()]


def _ocr_tesseract(img):
    import os
    import shutil
    import subprocess
    exe = shutil.which("tesseract")
    if not exe:
        raise ImportError("tesseract not on PATH")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    r = subprocess.run([exe, "stdin", "stdout", "--psm", "3", "-l", "eng"], input=buf.getvalue(),
                       capture_output=True, timeout=OCR_TIMEOUT, env={**os.environ, "OMP_THREAD_LIMIT": "1"})
    return [l.strip() for l in r.stdout.decode("utf-8", "replace").splitlines() if l.strip()]


_rapid = None


def _ocr_rapidocr(img):
    global _rapid
    if _rapid is None:
        from rapidocr_onnxruntime import RapidOCR
        _rapid = RapidOCR()
    import numpy as np
    res, _ = _rapid(np.asarray(img.convert("RGB")))
    return [r[1] for r in (res or [])]


OCR_ENGINES = {"apple": _ocr_apple, "tesseract": _ocr_tesseract, "rapidocr": _ocr_rapidocr}
_engine = None


def ocr_engine() -> str:
    """Name of the OCR engine in use ("none" when nothing is available)."""
    global _engine
    if _engine is None:
        import os
        from PIL import Image
        want = os.environ.get("FIREWALL_OCR", "auto")
        order = list(OCR_ENGINES) if want == "auto" else [want]
        _engine = "none"
        probe = Image.new("RGB", (8, 8), "white")
        for name in order:
            if name in OCR_ENGINES:
                try:
                    OCR_ENGINES[name](probe)
                    _engine = name
                    break
                except Exception:
                    continue
    return _engine


def _ocr_lines(img) -> list[str]:
    name = ocr_engine()
    if name == "none":
        return []
    try:
        return OCR_ENGINES[name](img)
    except Exception:
        return []


def _ocr(img) -> str:
    return " ".join(_ocr_lines(img))


def _stretch(img):
    """Contrast-stretch so near-invisible text (e.g. #FAFAFA on white) becomes legible to OCR."""
    from PIL import ImageOps

    g = ImageOps.grayscale(img)
    lo, hi = g.getextrema()
    if hi - lo < 1:
        return None
    # equalize amplifies tiny luminance differences to full range
    return ImageOps.equalize(g).convert("RGB")


def image_metadata(data: bytes, img) -> list[str]:
    found = []
    info = getattr(img, "info", {}) or {}
    for k, v in info.items():
        if k in ("exif", "icc_profile", "dpi", "jfif", "jfif_version", "jfif_unit", "jfif_density", "adobe", "adobe_transform", "progressive", "progression", "gamma", "transparency", "photoshop"):
            continue
        if isinstance(v, bytes):
            v = v.decode("utf-8", "ignore")
        if isinstance(v, str) and v.strip():
            found.append(f"{k}: {v.strip()}")
    try:
        exif = img.getexif()
        from PIL import ExifTags
        for tid, v in list(exif.items()) + list(exif.get_ifd(0x8769).items()):
            name = ExifTags.TAGS.get(tid, str(tid))
            if name in ("ImageDescription", "UserComment", "XPComment", "XPTitle", "XPSubject", "Artist", "Copyright", "Software", "Make", "Model"):
                if isinstance(v, bytes):
                    v = v.replace(b"\x00", b"").decode("utf-8", "ignore")
                    v = re.sub(r"^(ASCII|UNICODE)\s*", "", v)
                if str(v).strip():
                    found.append(f"exif {name}: {str(v).strip()}")
    except Exception:
        pass
    m = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", data, re.S)
    if m:
        xmp = re.sub(r"<[^>]+>", " ", m.group(0).decode("utf-8", "ignore"))
        xmp = re.sub(r"\s+", " ", xmp).strip()
        if xmp:
            found.append(f"xmp: {xmp}")
    # data smuggled after the JPEG end-of-image marker
    if data[:2] == b"\xff\xd8":
        eoi = data.rfind(b"\xff\xd9")
        tail = data[eoi + 2:] if eoi != -1 else b""
        if len(tail.strip(b"\x00")) > 8:
            t = tail.decode("utf-8", "ignore")
            if _printable_ratio(t) > 0.9:
                found.append(f"trailing data after JPEG end: {t.strip()}")
    return found


def extract_image(data: bytes) -> Extracted:
    from PIL import Image

    out = Extracted(text="")
    img = Image.open(io.BytesIO(data))
    img.load()
    meta = image_metadata(data, img)
    rgb = img.convert("RGB")
    plain = _ocr(rgb)
    # small print (e.g. 11 px footers): OCR 2x2 overlapping tiles upscaled 3x
    small = []
    if ocr_engine() not in ("apple", "none") and max(rgb.size) <= 2400:
        # slower engines: one 2x pass over the whole image (4x the pixels) instead of four 3x tiles
        # (16x): same recall on the benchmark's small-print images at half the time
        up = rgb.resize((rgb.width * 2, rgb.height * 2), Image.LANCZOS)
        small.extend(line for line in _ocr_lines(up) if line.lower() not in plain.lower())
    elif ocr_engine() == "apple" and max(rgb.size) <= 2400:
        W, H = rgb.size
        ox, oy = W // 12, H // 12
        for x0, y0 in ((0, 0), (W // 2, 0), (0, H // 2), (W // 2, H // 2)):
            box = (max(0, x0 - ox), max(0, y0 - oy), min(W, x0 + W // 2 + ox), min(H, y0 + H // 2 + oy))
            tile = rgb.crop(box)
            tile = tile.resize((tile.width * 3, tile.height * 3), Image.LANCZOS)
            small.extend(line for line in _ocr_lines(tile) if line.lower() not in plain.lower())
    stretched_img = _stretch(rgb)
    stretched = _ocr(stretched_img) if stretched_img is not None else ""
    # text that only appears after contrast stretching was invisible to a human
    extra = [w for w in stretched.split() if w.lower() not in plain.lower()]
    parts = []
    if plain:
        parts.append("[image text]: " + plain)
    small = list(dict.fromkeys(small))
    if small:
        if sum(len(l.split()) for l in small) >= 5:
            out.flags.append("image_small_text")
        parts.append("[small image text]: " + " ".join(small))
    if len(extra) >= 5:
        out.flags.append("image_low_contrast_text")
        out.revealed.append(stretched)
        parts.append("[faint image text]: " + stretched)
    if any(not m.startswith(("exif Make:", "exif Model:", "exif Software:")) for m in meta):
        out.flags.append("image_metadata_text")
        out.revealed.extend(meta)
        parts.append("[image metadata]: " + "\n".join(meta))
    if any(m.startswith("trailing data") for m in meta):
        out.flags.append("jpeg_trailing_data")
    if ocr_engine() == "none":
        out.flags.append("ocr_unavailable")
    out.text = collapse_opaque("\n".join(parts))
    return out


# File signatures: PNG, GIF, WebP (RIFF container) and JPEG.
IMAGE_SIGNATURES = (bytes.fromhex("89504e47"), b"GIF8", b"RIFF", bytes.fromhex("ffd8"))


def extract(content: str | bytes, kind: str = "auto") -> Extracted:
    if isinstance(content, bytes):
        if kind == "image" or content.startswith(IMAGE_SIGNATURES):
            return extract_image(content)
        content = content.decode("utf-8", "replace")
    out = Extracted(text="")
    text = reveal_unicode(content, out)
    if kind == "html" or (kind == "auto" and looks_like_html(text)):
        text = html_to_text(text, out)
    text = reveal_base64(text, out)
    out.text = collapse_opaque(text)
    return out
