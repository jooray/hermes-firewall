"""Verdict from signals, computed in code (the model is never asked for a verdict).

score      = aggregation of Laya question probabilities (fitted on the dev split)
injection  = score >= block threshold
suspicious = score >= warn threshold, or content was hidden from humans
             (invisible Unicode, base64 text, sentences in HTML ids, tiny/faint image text,
             data after a JPEG end marker), or part of the content was not scanned
             (no OCR engine, OCR failed, an image that could not be read, a chunk limit)
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field

# html_hidden_text is informational only: every real page hides menus and screen-reader text.
# The hidden text itself is still scored.
HIDING_FLAGS = ("unicode_tags", "zero_width", "base64_text", "html_attribute_text", "image_small_text",
                "image_low_contrast_text", "jpeg_trailing_data", "bidi_override")
# Part of the input never reached the detector. An incomplete scan must not read as "safe".
INCOMPLETE_FLAGS = {
    "ocr_unavailable": "image text not read (no OCR engine)",
    "ocr_failed": "image text not read (OCR failed)",
    "image_unreadable": "image could not be decoded",
    "scan_truncated": "content longer than the detector's chunk limit; the rest was not scored",
    "scan_incomplete": "part of the content could not be scored",
}

REASON = {
    "addressed_ai": "instructions addressed to an AI",
    "override": "tries to replace the reader's task",
    "off_topic_task": "embedded unrelated command",
    "covert": "asks for covert action or data disclosure",
    "imperative_to_reader": "commands the reader",
    "respond_format": "dictates the reader's response",
    "noul_injection": "reads as a planted prompt injection",
    "choice_kind": "reads as an instruction aimed at an AI",
}


@dataclass
class Policy:
    questions: list[str] = field(default_factory=lambda: ["addressed_ai"])
    agg: str = "max"                      # max | mean | logistic
    weights: dict = field(default_factory=dict)   # logistic only
    intercept: float = 0.0
    block: float = 0.9
    warn: float = 0.7
    hiding_escalates: bool = True         # hidden content => at least suspicious
    fitted_on: str = "defaults"
    backend: str = "laya"                 # laya | semif: which single model the service loads
    model: str = ""                       # checkpoint id ("" = backend default)
    revision: str = ""
    bits: int | None = None               # semif only: in-memory 4/8-bit quantization
    local_block: float | None = None      # block level for local files/shell output (None: plugin default)

    @classmethod
    def load(cls, path: str | None, backend: str = "laya") -> "Policy":
        """The bundled policy-<backend>.json, or a policy file. A missing policy is an error:
        silently falling back to unfitted defaults would run a configuration nobody measured."""
        if not path:
            if backend == "none":  # OCR-only service: no scoring, no thresholds
                return cls(backend="none")
            from importlib.resources import files
            try:
                return cls(**json.loads(files("hermes_firewall").joinpath(f"policy-{backend}.json").read_text()))
            except FileNotFoundError:
                raise FileNotFoundError(
                    f"no bundled policy-{backend}.json; fit one (bench/compare_variants.py --write-policy) "
                    "or pass --policy") from None
        with open(path) as f:
            return cls(**json.load(f))

    def describe(self) -> dict:
        return asdict(self)

    def score(self, sig: dict) -> float:
        vals = [sig.get(q, 0.0) for q in self.questions]
        if not vals:
            return 0.0
        if self.agg == "logistic":
            z = self.intercept + sum(self.weights.get(q, 0.0) * sig.get(q, 0.0) for q in self.questions)
            return 1.0 / (1.0 + math.exp(-z))
        return max(vals) if self.agg == "max" else sum(vals) / len(vals)

    def decide(self, sig: dict, flags: list[str]) -> dict:
        s = self.score(sig)
        hidden = [f for f in flags if f in HIDING_FLAGS]
        incomplete = [f for f in dict.fromkeys(flags) if f in INCOMPLETE_FLAGS]
        if s >= self.block:
            verdict = "injection"
        elif s >= self.warn or (self.hiding_escalates and hidden) or incomplete:
            verdict = "suspicious"
        else:
            verdict = "safe"
        reasons = [REASON.get(q, q) for q in self.questions if sig.get(q, 0) >= 0.8 and q in REASON]
        if not reasons and s >= self.warn:  # near the threshold no question is sure: name the closest
            q = max(self.questions, key=lambda q: sig.get(q, 0.0))
            reasons.append(f"closest: {REASON.get(q, q)} ({sig.get(q, 0.0):.2f})")
        reasons += [f"hidden content: {f}" for f in hidden]
        reasons += [f"not fully scanned: {INCOMPLETE_FLAGS[f]}" for f in incomplete]
        return {"verdict": verdict, "score": round(s, 4), "reasons": reasons}
