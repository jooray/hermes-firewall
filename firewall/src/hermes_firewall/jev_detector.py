"""Prompt-injection signals from Jev (TypeSafe System One) via Venice's Decisions API.

Stdlib only, so it also runs inside the Hermes plugin. Same interface as LayaDetector.score_many:
per text, {question: P(yes)} with the max over chunks. Long content is chunked, never truncated
(an attacker could pad ahead of the payload). Every chunk is tried; if any cannot be scored,
JevError is raised with the max over the chunks that were scored (`partial`), so a caller can keep
an injection already found, and with `outage` saying whether the service is failing (network,
auth, credit, rate limit: worth pausing) or only this input is (HTTP 500 on some content, a
rejected request, the scan deadline).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import threading
from concurrent.futures import ThreadPoolExecutor, wait

from .questions import QUESTIONS, chunk_text

URL = "https://api.venice.ai/api/v1/decisions"
RETRY_CODES = {429, 502, 503, 504}


class JevError(RuntimeError):
    def __init__(self, msg: str, *, outage: bool = True, partial: dict | None = None):
        super().__init__(msg)
        self.outage = outage      # the service is failing, not just this input
        self.partial = partial    # max over the chunks that were scored, or None


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
        self._pool = None         # one pool per detector: concurrent scans share its workers
        self._pool_lock = threading.Lock()

    def _executor(self) -> ThreadPoolExecutor:
        with self._pool_lock:
            if self._pool is None:
                self._pool = ThreadPoolExecutor(self.workers, thread_name_prefix="jev")
            return self._pool

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
                if e.code == 500:  # deterministic on some inputs: caller splits
                    raise JevError("HTTP 500", outage=False) from e
                if e.code not in RETRY_CODES:  # 400/413/422: this input; 401/402/403: key or credit
                    raise JevError(last, outage=e.code not in (400, 413, 422)) from e
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

    def _merge(self, parts: list[dict]) -> dict:
        return {q: max(p[q] for p in parts) for q in self.questions} | {"tokens": sum(p["tokens"] for p in parts)}

    def _score_chunk(self, chunk: str) -> dict:
        try:
            return self._call(chunk)
        except JevError as e:
            # Jev answers 500 "Inference processing failed" on some content; retry in smaller pieces.
            if str(e) != "HTTP 500" or len(chunk) <= 2000:
                raise
            parts, errors = [], []
            for c in chunk_text(chunk, 2000, 200):
                try:
                    parts.append(self._call(c))
                except JevError as pe:
                    errors.append(pe)
            if errors:
                raise JevError(str(errors[0]), outage=any(x.outage for x in errors),
                               partial=self._merge(parts) if parts else None)
            return self._merge(parts)

    def score_many(self, texts: list[str], deadline: float | None = None) -> list[dict]:
        """deadline: time.monotonic() value after which unscored chunks count as failed."""
        out = []
        for text in texts:
            t0 = time.perf_counter()
            chunks = chunk_text(text, self.chunk_chars, self.overlap) if text.strip() else []
            best = dict.fromkeys(self.questions, 0.0) | {"n_chunks": len(chunks), "tokens": 0}
            futures = [self._executor().submit(self._score_chunk, c) for c in chunks]
            timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
            done, pending = wait(futures, timeout=timeout)
            for f in pending:
                f.cancel()
            errors = [JevError("scan deadline reached", outage=False)] * len(pending)
            scored = 0
            for f in done:
                e = f.exception()
                if e is None:
                    res = f.result()
                else:
                    e = e if isinstance(e, JevError) else JevError(f"{type(e).__name__}: {e}")
                    errors.append(e)
                    res = e.partial
                if res:
                    scored += 1
                    for q in self.questions:
                        best[q] = max(best[q], res[q])
                    best["tokens"] += res["tokens"]
            best["ms"] = (time.perf_counter() - t0) * 1000
            if errors:
                raise JevError(f"{errors[0]} ({len(errors)} of {len(chunks)} chunks not fully scored)",
                               outage=any(x.outage for x in errors),
                               partial=best | {"failed_chunks": len(errors)} if scored else None)
            out.append(best)
        return out
