"""HTTP service: POST /v1/scan {text | image (base64 or data URL), source} -> verdict.

Stdlib only (plus the model). At most one model instance (Laya, SemIf or Jev; none in OCR-only mode), one
lock: requests are serialised rather than batched. Verdicts are cached by sha256 of the input.

Auth: bearer token (FIREWALL_TOKEN) and an optional source-IP allowlist
(FIREWALL_ALLOW, comma-separated). Both unset = open, which is only sane on
127.0.0.1.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .extract import extract
from .policy import Policy

log = logging.getLogger("hermes_firewall")
MAX_IMAGE = 15 * 1024 * 1024


class BadInput(ValueError):
    """The request itself is malformed (bad JSON or base64, an image that cannot be decoded):
    HTTP 400. Any other failure is the service's (no model, scoring backend down): HTTP 503,
    so a caller never mistakes an outage for a bad image."""


def _extract(content, kind="auto"):
    try:
        return extract(content, kind)
    except Exception as e:
        if kind == "image":  # Pillow could not open it
            raise BadInput(f"image could not be decoded: {e}") from e
        raise


class Firewall:
    def __init__(self, policy: Policy):
        # At most one model is loaded, chosen by the policy's backend. "none" loads no model:
        # the service then only extracts (OCR for images), and scoring happens in the caller.
        self.policy = policy
        self.lock = threading.Lock()
        self.cache: OrderedDict[str, dict] = OrderedDict()
        if policy.backend == "none":
            self.det = None
            return
        if policy.backend == "semif":
            from .semif_detector import QWEN_4B, SemIfDetector
            self.det = SemIfDetector(policy.model or QWEN_4B[0], policy.revision or QWEN_4B[1],
                                     policy.bits, questions=policy.questions)
        elif policy.backend == "jev":
            from .jev_detector import JevDetector
            key = os.environ.get("FIREWALL_VENICE_KEY", "")
            if not key and os.environ.get("FIREWALL_VENICE_KEY_FILE"):
                key = open(os.path.expanduser(os.environ["FIREWALL_VENICE_KEY_FILE"])).read().strip()
            self.det = JevDetector(key, questions=policy.questions)
        else:
            from .laya_detector import LayaDetector
            self.det = LayaDetector(policy.model or "aac6fef/laya-mlx", questions=policy.questions)
        self.det.score_many(["warm up"])

    def ocr(self, image: bytes) -> dict:
        """Extraction only (OCR + metadata), no scoring. Used by callers that score elsewhere."""
        t0 = time.perf_counter()
        ex = _extract(image, "image")
        return {"text": ex.text, "flags": ex.flags, "revealed": [r[:200] for r in ex.revealed][:5],
                "ms": {"extract": round((time.perf_counter() - t0) * 1000, 1)}}

    def scan(self, *, text: str | None = None, image: bytes | None = None) -> dict:
        t0 = time.perf_counter()
        key = hashlib.sha256((text or "").encode("utf-8", "ignore") if image is None else image).hexdigest()
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                return {**self.cache[key], "cached": True}
        # Text is never cut here: the detector chunks it, and a chunk limit raises scan_truncated.
        ex = _extract(image, "image") if image is not None else _extract(text)
        t1 = time.perf_counter()
        if self.det is None:
            raise RuntimeError("no scoring backend loaded (backend=none); use /v1/ocr")
        with self.lock:
            sig = self.det.score_many([ex.text])[0] if ex.text.strip() else {}
        if sig.get("truncated"):
            ex.flags.append("scan_truncated")
        res = self.policy.decide(sig, ex.flags)
        res.update(flags=ex.flags, revealed=[r[:200] for r in ex.revealed][:5],
                   signals={k: round(v, 4) for k, v in sig.items() if isinstance(v, float)},
                   ms={"extract": round((t1 - t0) * 1000, 1), "total": round((time.perf_counter() - t0) * 1000, 1)})
        with self.lock:
            self.cache[key] = res
            if len(self.cache) > 8192:
                self.cache.popitem(last=False)
        return res


def make_handler(fw: Firewall, token: str, allow: set[str]):
    class H(BaseHTTPRequestHandler):
        server_version = "hermes-firewall/0.1"

        def log_message(self, fmt, *a):
            log.info("%s " + fmt, self.client_address[0], *a)

        def _send(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self):
            if allow and self.client_address[0] not in allow:
                return False
            if token:
                got = self.headers.get("Authorization", "")
                return hmac.compare_digest(got, f"Bearer {token}")
            return True

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"ok": True, "model": fw.det.name if fw.det else None,
                                        "policy": fw.policy.describe()})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            if self.path not in ("/v1/scan", "/v1/scan-image", "/v1/ocr"):
                return self._send(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_IMAGE * 2:
                return self._send(413, {"error": "too large"})
            req, data = {}, None
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(req, dict):
                    raise ValueError("request body must be a JSON object")
                if self.path == "/v1/ocr" or req.get("image"):
                    img = str(req.get("image") or "")
                    if img.startswith("data:"):
                        img = img.split(",", 1)[1]
                    data = base64.b64decode(img, validate=True)
            except Exception as e:
                return self._send(400, {"error": f"malformed request: {e}"[:200], "kind": "bad_input"})
            try:
                if self.path == "/v1/ocr":
                    res = fw.ocr(data)
                    log.info("ocr source=%s flags=%s ms=%s", req.get("source", "?"), ",".join(res["flags"]),
                             res["ms"]["extract"])
                    return self._send(200, res)
                res = fw.scan(image=data) if data is not None else fw.scan(text=str(req.get("text", "")))
            except BadInput as e:
                return self._send(400, {"error": str(e)[:200], "kind": "bad_input"})
            except Exception as e:  # the service failed, not the input: never a 400
                log.exception("scan failed")
                return self._send(503, {"error": str(e)[:200], "kind": "unavailable"})
            log.info("scan source=%s verdict=%s score=%.3f flags=%s ms=%s", req.get("source", "?"),
                     res["verdict"], res["score"], ",".join(res["flags"]), res["ms"]["total"])
            self._send(200, res)

    return H


def main():
    ap = argparse.ArgumentParser(description="hermes-firewall scanning service")
    ap.add_argument("--host", default=os.environ.get("FIREWALL_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("FIREWALL_PORT", "9030")))
    ap.add_argument("--backend", choices=["laya", "semif", "jev", "none"], default=os.environ.get("FIREWALL_BACKEND", "laya"),
                    help="which single model to load; picks the bundled policy-<backend>.json")
    ap.add_argument("--policy", default=os.environ.get("FIREWALL_POLICY"), help="policy JSON (overrides --backend)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    token = os.environ.get("FIREWALL_TOKEN", "")
    tf = os.environ.get("FIREWALL_TOKEN_FILE")
    if tf and not token:
        token = open(os.path.expanduser(tf)).read().strip()
    allow = {a.strip() for a in os.environ.get("FIREWALL_ALLOW", "").split(",") if a.strip()}
    if args.host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise SystemExit("refusing to listen on a non-loopback address without FIREWALL_TOKEN")
    fw = Firewall(Policy.load(args.policy, args.backend))
    srv = ThreadingHTTPServer((args.host, args.port), make_handler(fw, token, allow))
    log.info("listening on %s:%d model=%s", args.host, args.port, fw.det.name if fw.det else "none (OCR only)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
