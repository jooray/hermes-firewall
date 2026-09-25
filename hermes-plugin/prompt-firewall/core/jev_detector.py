"""Prompt-injection signals from Jev (TypeSafe System One) via Venice's Decisions API.

Stdlib only, so it also runs inside the Hermes plugin. Same interface as LayaDetector.score_many:
per text, {question: P(yes)} with the max over chunks. Long content is chunked, never truncated
(an attacker could pad ahead of the payload). Any chunk that cannot be scored raises JevError, so
the caller can fail closed instead of passing unscanned content.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .questions import QUESTIONS, chunk_text

URL = "https://api.venice.ai/api/v1/decisions"
RETRY_CODES = {429, 502, 503, 504}


class JevError(RuntimeError):
    pass


def p_yes(ans: dict) -> float:
    if ans["type"] == "noul":
        return float(ans["noul"])
    if ans["type"] == "choice":
        return float(ans["probabilities"].get("injection", 0.0))
    probs = ans["probabilities"]
    return float(probs[str(max(int(k) for k in probs))])  # score: P(top rubric level)


class JevDetector:
    def __init__(self, api_key: str, model: str = "jev-latest", questions: list[str] | None = None,
                 chunk_chars: int = 12000, overlap: int = 400, timeout: float = 20.0, attempts: int = 3,
                 workers: int = 4, url: str = URL, max_wait: float = 20.0):
        if not api_key:
            raise JevError("no Venice API key")
        self.key, self.model, self.url = api_key, model, url
        self.name = f"{model} (Venice)"
        self.questions = {q: QUESTIONS[q] for q in (questions or QUESTIONS)}
        self.chunk_chars, self.overlap = chunk_chars, overlap
        self.timeout, self.attempts, self.workers = timeout, attempts, workers
        self.max_wait = max_wait  # longest rate-limit wait before failing (closed) instead

    def _call(self, state: str) -> dict:
        body = json.dumps({"model": self.model, "state": state, "questions": self.questions}).encode()
        last = None
        for attempt in range(self.attempts):
            req = urllib.request.Request(self.url, data=body, headers={
                "Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    res = json.load(r)
                return {q: p_yes(a) for q, a in res["answers"].items()} | {
                    "tokens": res.get("usage", {}).get("input_tokens", 0)}
            except urllib.error.HTTPError as e:
                last = f"HTTP {e.code}"
                if e.code == 500:
                    raise JevError("HTTP 500") from e  # deterministic on some inputs: caller splits
                if e.code not in RETRY_CODES:
                    raise JevError(last) from e
                if e.code == 429:  # per-key limit (e.g. 100 requests/min): wait for the reported reset
                    reset = e.headers.get("x-ratelimit-reset-requests") or ""
                    wait = (int(reset) / 1000 - time.time()) if reset.isdigit() else 5.0
                    if wait > self.max_wait:
                        raise JevError(f"rate limited for {wait:.0f}s") from e
                    time.sleep(max(1.0, wait))
                    continue
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last = type(e).__name__
            time.sleep(0.5 * 2 ** attempt)
        raise JevError(f"gave up after {self.attempts} attempts ({last})")

    def _score_chunk(self, chunk: str) -> dict:
        try:
            return self._call(chunk)
        except JevError as e:
            # Jev answers 500 "Inference processing failed" on some content; retry in smaller pieces.
            if str(e) != "HTTP 500" or len(chunk) <= 2000:
                raise
            parts = [self._call(c) for c in chunk_text(chunk, 2000, 200)]
            return {q: max(p[q] for p in parts) for q in self.questions} | {
                "tokens": sum(p["tokens"] for p in parts)}

    def score_many(self, texts: list[str]) -> list[dict]:
        out = []
        with ThreadPoolExecutor(self.workers) as ex:
            for text in texts:
                t0 = time.perf_counter()
                chunks = chunk_text(text, self.chunk_chars, self.overlap) if text.strip() else []
                best = dict.fromkeys(self.questions, 0.0) | {"n_chunks": len(chunks), "tokens": 0}
                for res in ex.map(self._score_chunk, chunks):
                    for q in self.questions:
                        best[q] = max(best[q], res[q])
                    best["tokens"] += res["tokens"]
                best["ms"] = (time.perf_counter() - t0) * 1000
                out.append(best)
        return out
