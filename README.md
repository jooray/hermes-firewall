# hermes-firewall

A prompt-injection gate for [Hermes Agent](https://github.com/NousResearch/hermes-agent). It scans
untrusted content before the agent's model sees it: web pages, MCP and tool results, fetched email,
files and images. Each result is either passed unchanged or withheld.

**Background:** [A prompt-injection gate for my AI agent: what worked, what didn’t, and the benchmark](https://juraj.bednar.io/en/blog-en/2026/09/28/a-prompt-injection-gate-for-my-ai-agent-what-worked-what-didnt-and-the-benchmark/)

**Install:** follow [`INSTALL.md`](INSTALL.md). It is written so your Hermes agent can do most of it
for you. In short: `hermes plugins install jooray/hermes-firewall/hermes-plugin/prompt-firewall --enable`,
a Venice API key in a file, optionally Tesseract for images, then a restart. It needs no second
machine and installs nothing into Hermes' Python environment.

## How it works

1. **Extract** (local, standard-library Python inside the plugin). The scanner has to see at least
   what the model sees. Extraction keeps the visible text, then appends the text a human would not
   see:
   - hidden HTML elements and comments, and sentence-like attribute values (`id`, `data-*`, `alt`…);
   - `<meta>` content, JSON-LD, and `<script>` strings and comments;
   - invisible Unicode tag characters, and decoded base64.

   Fragments shorter than three words in attributes and scripts are dropped as markup noise. Long
   random tokens (ids, keys, base64) become a placeholder, unless they are words joined by `_` or
   `-`, which stay readable.

   Images are OCR'd (Tesseract, or Apple Vision on macOS if `ocrmac` is installed), including small
   print and near-white text. Their metadata is read too: EXIF, XMP, comments, and bytes after the
   JPEG end marker.
2. **Score** with [Jev](https://venice.ai/lp/jev), a decision model on Venice's Decisions API. It
   answers two questions about the text and returns calibrated probabilities, not generated text.
   Long content is chunked, never truncated.
3. **Decide** with a threshold fitted on a labelled dev set: block, or pass unchanged. The plugin
   never adds text to a result, because a warning prefix would break the JSON Hermes parses from
   tool results. A second, lower threshold only marks a scan as `flagged` in the log, as do content
   hidden with certain techniques (invisible Unicode, base64, a sentence in an HTML `id`, tiny or
   faint image text) and results the scanner could not fully read (no OCR, a failed OCR run, an
   undecodable or remote image).
4. **Log** every scan, without the scanned content, to `~/.hermes/firewall/scans.jsonl`.

The plugin wraps Hermes' `tool_execution` middleware, so the scan finishes before a result enters
the transcript. Every tool is scanned except a short list whose results carry no outside content
(memory, todo, writes, UI actions); [`INSTALL.md`](INSTALL.md) has the full table. A second hook,
`llm_request`, covers cron script output pasted into prompts. Scanning failures, such as no Venice
credit or an outage, **fail open** by default, so the agent keeps working, and the log records every
unscanned result. Details: [`docs/hermes-integration.md`](docs/hermes-integration.md).

## How well it works

A benchmark built only from public data: BIPIA emails with planted instructions, deepset, Lakera
Gandalf, real Nostr posts, and web pages *about* prompt injection as hard negatives. The same
attack strings were also hidden in HTML, markup, invisible Unicode, base64, images and image
metadata. Thresholds were fitted on a separate dev split. The table uses 718 test items (433
attacks): test items whose extracted text also occurs in dev are left out. The pipeline was developed
iteratively, so treat these numbers as exploratory.

| Detector | Test AUC | Planted email instructions | Caught at dev 2% threshold (test FP) |
|---|---:|---:|---:|
| **Jev** (Venice, ~0.5 s, ~$0.035 per 1,000 scans on this corpus) | **0.981** | **1.000** | **88.9%** (3.5%) |
| SemIf with Qwen3.5-4B, 8-bit (local, 6 GB, ~1.3 s) | 0.931 | 0.973 | 68.1% (4.9%) |
| ProtectAI deberta-v3 prompt-injection v2 | 0.813 | 0.433 | 49.4% (4.6%) |
| Laya 421M (local, 1 GB) | 0.790 | 0.543 | 39.5% (4.9%) |
| Keyword regex | 0.602 | – | 21.5% (1.1%) |

With its shipped thresholds, Jev blocks 88.5% of the attacks and 3.5% of the benign items.

Small classifiers catch jailbreak phrasing but are at chance on an ordinary-looking instruction
planted in an ordinary email; SemIf and Jev separated those reliably. These numbers measure the
detector on single items, not how often an agent running the plugin would be compromised. Full results and caveats are in
[`bench/RESULTS.md`](bench/RESULTS.md). The main caveats:
- the attack datasets are public, and Jev's training data is unknown;
- nothing was tested against an attacker adapting to the detector.

Treat this as one layer. Keep the agent's tool permissions tight regardless.

## Repository layout

| Path | What |
|---|---|
| `hermes-plugin/prompt-firewall/` | The Hermes plugin. `core/` is vendored from `firewall/src` by `hermes-plugin/sync_core.sh`. Don't edit it directly. |
| `firewall/` | The same extraction code as a package, plus an optional HTTP service. The service scores with **one local model** (Laya on MLX, or SemIf/Qwen3.5-4B) for setups that must not use a cloud scorer. The plugin then uses `PROMPT_FIREWALL_BACKEND=service`. |
| `bench/` | Corpus builder, scorers, evaluation and results. |
| `docs/` | How the plugin hooks into Hermes. |

### Optional: the local scanning service (Apple Silicon)

```bash
cd firewall
uv sync                       # add --extra semif for the SemIf backend
FIREWALL_TOKEN=$(openssl rand -hex 32) uv run hermes-firewall --backend laya --host 127.0.0.1 --port 9030
```

`POST /v1/scan {"text": ...}` and `POST /v1/scan-image {"image": "<base64>"}` return
`{verdict, score, reasons, flags, ...}`. `POST /v1/ocr` returns only the extracted text.
`--backend none` loads no model and serves OCR only. A non-loopback address requires a token;
`FIREWALL_ALLOW` adds a source-IP allowlist. Under launchd, set `ProcessType=Interactive`, or
macOS runs it on efficiency cores.

## Development

```bash
uv run --no-project --with httpx --with pytest --with pillow pytest hermes-plugin/test_plugin.py firewall/tests
hermes-plugin/sync_core.sh    # after changing firewall/src
```

Reproduce the benchmark:

```bash
cd bench
./fetch_data.sh               # BIPIA, deepset, Gandalf, Nostr sample, 10 web pages
uv sync && uv run python build_corpus.py && uv run python add_attr_carriers.py && uv run python extract_corpus.py
uv run python score_regex.py && uv run python score_deberta.py
uv run python score_laya.py aac6fef/laya-mlx laya_en
VENICE_API_KEY=... uv run python score_jev.py          # through the plugin's own Jev client
# SemIf: clone callebtc/decision-tools next to this repo and set up decision-tools/Semif, then
#   ../decision-tools/Semif/.venv/bin/python score_semif.py   (SEMIF_BITS=8 SEMIF_TAG=semif_q8 for 8-bit)
uv run python compare_jev_questions.py --write-policy    # policy-jev.json; compare_variants.py --write-policy semif_q8 for SemIf
uv run python blog_charts.py                             # the README/blog numbers and charts
```

Built on [callebtc/decision-tools](https://github.com/callebtc/decision-tools), which showed how to
use Laya and SemIf as zero-output-token classifiers.

## License

MIT. Datasets keep their own licenses (BIPIA: MIT, deepset/prompt-injections: Apache-2.0, Lakera
Gandalf: MIT) and are downloaded by `bench/fetch_data.sh`, not redistributed.
