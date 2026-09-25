"""Verdict from signals, computed in code (the model is never asked for a verdict).

score      = aggregation of Laya question probabilities (fitted on the dev split)
injection  = score >= block threshold
suspicious = score >= warn threshold, or content was hidden from humans
             (invisible Unicode, hidden HTML, base64 text, tiny/faint image text,
             data after a JPEG end marker)
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field

# html_hidden_text is informational only: every real page hides menus and screen-reader text.
HIDING_FLAGS = ("unicode_tags", "zero_width", "base64_text", "html_attribute_text", "image_small_text",
                "image_low_contrast_text", "jpeg_trailing_data", "bidi_override")

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

    @classmethod
    def load(cls, path: str | None, backend: str = "laya") -> "Policy":
        if not path:
            from importlib.resources import files
            try:
                return cls(**json.loads(files("hermes_firewall").joinpath(f"policy-{backend}.json").read_text()))
            except FileNotFoundError:
                return cls(backend=backend)
        return cls(**json.load(open(path)))

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
        if s >= self.block:
            verdict = "injection"
        elif s >= self.warn or (self.hiding_escalates and hidden):
            verdict = "suspicious"
        else:
            verdict = "safe"
        reasons = [REASON.get(q, q) for q in self.questions if sig.get(q, 0) >= 0.8 and q in REASON]
        reasons += [f"hidden content: {f}" for f in hidden]
        return {"verdict": verdict, "score": round(s, 4), "reasons": reasons}
