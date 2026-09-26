"""Prompt-injection signals from Laya (laya-mlx), batched over chunks x questions.

Laya's sequence is capped at 512 tokens (1,024 for the multilingual checkpoint)
including the question, and the state is truncated from the end, so long
content is split into overlapping chunks and each signal is the max over chunks.
Probabilities are decoded exactly like Agent.system_one (calibrated softmax
over the option markers). The verdict is computed by the caller from these
signals, never asked of the model (decision-tools finding: model-asked
verdicts were the worst signal).
"""

from __future__ import annotations

import numpy as np

from .questions import QUESTIONS, chunk_text  # noqa: F401  (re-exported)


class LayaDetector:
    def __init__(self, model: str = "aac6fef/laya-mlx", chunk_chars: int | None = None,
                 overlap: int = 200, max_chunks: int = 40, batch_size: int = 64,
                 questions: list[str] | None = None):
        import laya_mlx as laya

        self.agent = laya.load(model, batch_size=batch_size)
        self.name = model
        self.questions = {q: QUESTIONS[q] for q in (questions or QUESTIONS)}
        max_len = self.agent.cfg.get("max_len", 512)
        # ~3.5 chars/token, minus the question head budget
        self.chunk_chars = chunk_chars or int((max_len - 200) * 3.5)
        self.overlap = overlap
        self.max_chunks = max_chunks

    def _decode(self, logits_row, item):
        from laya_mlx.common import temp_bucket

        qt, k = item["qtype"], len(item["markers"])
        scale = self.agent.temperature_by_options.get(temp_bucket(qt, k), self.agent.temperature[qt])
        z = logits_row[:k] / max(1e-3, float(scale))
        p = np.exp(z - z.max())
        return p / p.sum()

    def score_many(self, texts: list[str]) -> list[dict]:
        """Return, per text, {question: max-over-chunks p(yes)} plus n_chunks."""
        import mlx.core as mx
        from laya_mlx.agent import collate_items

        items, owners = [], []
        out = [dict.fromkeys(self.questions, 0.0) for _ in texts]
        for ti, text in enumerate(texts):
            if not text.strip():  # nothing to score; Laya rates empty input as suspicious
                out[ti]["n_chunks"] = 0
                continue
            chunks = chunk_text(text, self.chunk_chars, self.overlap)
            out[ti]["truncated"] = len(chunks) > self.max_chunks  # reported, never silent
            chunks = chunks[: self.max_chunks]
            out[ti]["n_chunks"] = len(chunks)
            for ch in chunks:
                prepared, _ = self.agent.prepare(ch, self.questions)
                for qname, it in zip(self.questions, prepared):
                    items.append(it)
                    owners.append((ti, qname))
        bs = self.agent.batch_size
        max_len = self.agent.cfg.get("max_len", 512)
        for start in range(0, len(items), bs):
            chunk = items[start:start + bs]
            batch = collate_items(chunk, self.agent.tok.pad_token_id,
                                  pad_to_multiple=self.agent.pad_to_multiple, max_length=max_len)
            logits, _ = self.agent.forward(batch)
            logits = np.asarray(logits)
            for row, it in enumerate(chunk):
                ti, qname = owners[start + row]
                p = self._decode(logits[row], it)
                out[ti][qname] = max(out[ti][qname], float(p[-1]))
        try:
            mx.clear_cache()
        except Exception:
            pass
        return out
