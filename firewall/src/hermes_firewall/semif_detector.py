"""Prompt-injection signals from SemIf (answer-token logits of a frozen instruction model).

Same interface as LayaDetector.score_many. Each question is a SemIf decision row
whose option descriptions are the rubric anchors; the signal is P(last option),
max over chunks. One shared-prefix pass per chunk scores all questions.
"""

from __future__ import annotations

from .laya_detector import QUESTIONS, chunk_text

QWEN_4B = ("Qwen/Qwen3.5-4B", "851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a")


class SemIfDetector:
    def __init__(self, model: str = QWEN_4B[0], revision: str = QWEN_4B[1], bits: int | None = None,
                 questions: list[str] | None = None, chunk_chars: int = 6000, overlap: int = 300,
                 max_chunks: int = 6):
        from semif_phase1 import mlx_backend

        self._mlx = mlx_backend
        self.model, self.tokenizer, self.meta = mlx_backend.load_model(model, revision, bits)
        self.name = f"{model}@{revision[:8]}" + (f" q{bits}" if bits else "")
        qs = questions or [q for q, d in QUESTIONS.items() if d["type"] == "score"]
        self.questions = {q: QUESTIONS[q] for q in qs}
        self.chunk_chars, self.overlap, self.max_chunks = chunk_chars, overlap, max_chunks

    def _rows(self, chunk: str) -> list[dict]:
        return [{"id": q, "state": chunk, "question": d["instructions"],
                 "options": [{"id": str(i), "description": c} for i, c in enumerate(d["criteria"])]}
                for q, d in self.questions.items()]

    def score_many(self, texts: list[str]) -> list[dict]:
        import mlx.core as mx

        out = []
        for text in texts:
            best = dict.fromkeys(self.questions, 0.0)
            chunks = chunk_text(text, self.chunk_chars, self.overlap)[: self.max_chunks] if text.strip() else []
            for ch in chunks:
                rows = self._rows(ch)
                try:
                    res, _ = self._mlx.score_shared(self.model, self.tokenizer, rows, self.meta)
                except ValueError:  # shared-prefix check can fail on tokenization boundaries
                    res = [self._mlx.score(self.model, self.tokenizer, r, self.meta) for r in rows]
                for r in res:
                    best[r["id"]] = max(best[r["id"]], r["probabilities"][-1])
            best["n_chunks"] = len(chunks)
            out.append(best)
        try:
            mx.clear_cache()
        except Exception:
            pass
        return out
