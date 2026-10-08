# Installing prompt-firewall into Hermes Agent

These steps are written so that a Hermes agent can carry them out for its owner. They are also fine
for a person to follow. If you install from a fork, use its path instead of `jooray/hermes-firewall`.

Everything runs on the machine that runs Hermes. Nothing is installed into Hermes' Python
environment: the plugin uses only the standard library plus Pillow and httpx, which Hermes ships.

**Rules for an agent doing this:**
- Never ask for the Venice API key in chat and never print it. The owner writes it into a file
  themselves (step 3).
- Steps marked **owner** need the owner: `sudo`, the key, and the restart. A Hermes agent that
  restarts its own service ends its current turn, so ask the owner to restart it.
- Show each command's output. If a step fails, stop and report; don't improvise.

## 1. Install the plugin

```bash
hermes plugins install jooray/hermes-firewall/hermes-plugin/prompt-firewall --enable
hermes plugins list | grep prompt-firewall        # expect: prompt-firewall  enabled
```

Hermes warns that this is a custom (unreviewed) source. That is expected.

## 2. OCR for images (optional, **owner**: needs sudo or Homebrew)

Install Tesseract:

| System | Command |
|---|---|
| macOS | `brew install tesseract` |
| Arch | `sudo pacman -S tesseract tesseract-data-eng` |
| Debian / Ubuntu | `sudo apt install tesseract-ocr` |
| Fedora | `sudo dnf install tesseract` |

Check with `tesseract --version`. On macOS the plugin prefers Apple Vision, which reads small and
faint text better, but only when the `ocrmac` package is installed in Hermes' own virtual
environment. Hermes does not ship it. To add it, find the interpreter the `hermes` command runs
with and install into that environment:

```bash
head -1 "$(command -v hermes)"                          # e.g. #!/path/to/venv/bin/python
uv pip install --python /path/to/venv/bin/python ocrmac  # the path from the line above
```

Without any OCR engine, image metadata is still scanned and every image is marked suspicious,
because its pixels were not read. An OCR run that fails or times out is treated the same way.
Images take roughly 0.5 s each on a laptop and ~10 s on a small Celeron-class server; text scans
don't use OCR.

## 3. Venice API key (**owner**)

Extraction and OCR run locally, but the extracted text of every scanned result (web pages, email,
files, text read from images) is sent to Venice for scoring. If that is not acceptable, score
locally with Nimble or RSI-Jev instead (section 3b) and skip this section.

Scoring uses Jev through Venice's Decisions API. On the benchmark corpus it cost about $0.035 per
1,000 scans; long pages are split into several requests and cost more. Create a
**dedicated** key in the Venice dashboard; a spending cap is a good idea. The rate limit is per
key (100 requests a minute on the key tested), and a long page uses several requests, so sharing
the agent's own key would slow both. The owner writes the key into a file containing only the key:

```bash
umask 077; cat > ~/.venice-firewall-key       # paste the key, press Enter, then Ctrl-D
```

## 3b. Or: score locally with Nimble in Ollama (**owner**)

Instead of Jev, the plugin can use Nimble, a local decision model served by Ollama 0.35 or later.
Nothing leaves the machine and no key is needed. The price: on the benchmark it blocked 78% of
attacks against Jev's 89%, and 63% of instructions planted in email against Jev's 92% (details
in `bench/RESULTS.md`). It also needs the memory and a fast machine: about 11 GB for the default
4-bit build, and on an Apple M2 Max a short message takes ~2 s and a long web page 15 s or more.
A small server without a GPU is too slow for it.

```bash
ollama --version                  # 0.35.0 or later
ollama pull nimble:9b-q4_K_M      # 5.6 GB download; or nimble:9b (8-bit, 9.5 GB, ~15 GB in use)
```

Then set, in the same place as the other settings (section 4):

```bash
PROMPT_FIREWALL_BACKEND=nimble
# PROMPT_FIREWALL_MODEL=nimble:9b-q4_K_M      # the default; nimble:9b for the 8-bit build
# PROMPT_FIREWALL_OLLAMA_URL=http://127.0.0.1:11434
```

Each model has its own thresholds, fitted on the benchmark's development split
(`core/policy-nimble-9b-q4_K_M.json`, `core/policy-nimble-9b.json`); scores from different models
are not on the same scale. Any other model is refused (logged as a scanner error) rather than
run with thresholds nobody measured. With this backend the per-request timeout defaults to 60 s
and the whole-scan deadline to 120 s. If Ollama is not running, scanning fails open like a Venice
outage.

Any local server that speaks Jev's `/v1/systemone` works the same way (the backend is also
aliased `local`). [RSI-Jev](https://github.com/Shanghua-Gao/RSI-Jev) v6.1-VL 4B is benchmarked
too (`bench/RESULTS.md`): on an Apple M2 Max it is the strongest local model by overall ranking
(test AUC 0.940 against Nimble's 0.927) and it answers short messages in ~1.3 s, but with its own
thresholds it blocks fewer instructions planted in email (50% against Nimble's 63%). To use it:

```bash
# in its own venv (it pins transformers < 5.18)
pip install "rsi-jev[vision] @ git+https://github.com/Shanghua-Gao/RSI-Jev"
rsi-jev serve v6.1-vl-4b --device mps --port 8000    # --device cuda on an NVIDIA machine
```

```bash
PROMPT_FIREWALL_BACKEND=local
PROMPT_FIREWALL_MODEL=rsi-jev-v6.1-vl-4b
PROMPT_FIREWALL_OLLAMA_URL=http://127.0.0.1:8000
```

Its fitted thresholds are in `core/policy-rsi-jev-v6.1-vl-4b.json`.

## 4. Settings

Append to `~/.hermes/.env` (make a backup first: `cp ~/.hermes/.env ~/.hermes/.env.bak`):

```
PROMPT_FIREWALL_VENICE_KEY_FILE=~/.venice-firewall-key
PROMPT_FIREWALL_WARN_ONLY=1
```

The plugin never edits a result. It either passes it unchanged or replaces the whole result with a
short JSON note saying it was blocked. Adding a warning to the text would break the JSON that Hermes
parses from tool results (exit codes, failure detection).

`WARN_ONLY=1` never blocks: what would have been blocked is only logged as `flagged`. Run with it
for a while on real traffic, review the flagged entries, then remove the line to start blocking.

Content is judged by where it came from, not by which tool read it. Content from outside (web, MCP,
email, `gh`, `curl`/`wget` and other fetch commands, the files those commands save, Hermes' own spill
files of large results) blocks at the policy's level, 0.38. Local content (files read with
`read_file`/`search_files`, output of local shell commands such as `cat notes.md` or
`python report.py`) blocks at a higher level, 0.6 (`PROMPT_FIREWALL_LOCAL_FILE_BLOCK`): the agent's
own notes (task lists, "next: do X") are what score just above 0.38 in practice. On the benchmark
this costs 4.3 points of recall (84.2% instead of 88.5% of attacks) and cuts benign blocks from
2.8% to 1.0%. Set the variable to 0.38 to use one level everywhere. Scores between the two levels
are logged as `flagged`. If mail, downloads or other outside content lands in a directory the agent
reads with file tools, list it in `PROMPT_FIREWALL_EXTERNAL_PATHS` (comma-separated) so it is judged
as outside content.

Output of a short list of commands that only report on the agent's own work (`git status`,
`git commit`, `mkdir`, `echo`, …) is never blocked, only logged. `PROMPT_FIREWALL_TRUSTED_COMMANDS`
adds command names to that list.

Two more things are never blocked, only logged: the harness' own instruction-like text (Hermes'
approval denials such as "BLOCKED: Command timed out … Do NOT retry", its terminal exit-code
hint, the `read_file` "File unchanged since last read" notice, delegate_task acknowledgements,
BrowserOS' page notes and session tips, the protective `<untrusted_tool_result>` /
`[UNTRUSTED_PAGE_CONTENT]` envelopes, and the plugin's own block notice, which a retry can print
back into a later result) is removed before scoring; and the results of the agent's own index
tools (`session_search`, `skill_view`, `tool_search`, `tool_describe`, `honcho_*`) are scanned
but never blocked. `PROMPT_FIREWALL_WARN_TOOLS` adds tool names to that warn-only list.
Removal is template-exact: text that merely looks like one of those messages is left in place
and scored, so nothing can be smuggled past the scanner by dressing it up as a first-party
message.

Scanning failures (no Venice credit, Venice down, a bug) **fail open** by default: content passes
through unscanned so the agent keeps working, and the log records it. Content already found to be
an injection is blocked even if a later part of the same result fails to scan. For strict setups,
`PROMPT_FIREWALL_ON_ERROR=closed` withholds every scanned source when scanning fails, except the
trusted commands above. With it, content the scan could not fully read (an image without OCR, a
remote or oversized image, a part Jev refused) is withheld too; `PROMPT_FIREWALL_ON_INCOMPLETE`
(`pass` or `block`) sets that separately. Every setting is listed in
`hermes-plugin/prompt-firewall/plugin.yaml`.

**Several profiles:** the scan log, quarantine and release list live under each profile's own Hermes
home. Settings can differ per profile in that profile's `config.yaml`; they override the
environment for that profile only:

```yaml
plugins:
  entries:
    prompt-firewall:
      settings:
        warn_only: true
        venice_key_file: ~/.venice-firewall-key-work   # a path, never the key itself
```

### What gets scanned

| Source | Examples | On injection | When scanning fails |
|---|---|---|---|
| External content | `web_*`, `x_search`, `browser_*`, `mcp_*`, `vision_analyze`, `computer_use`, shell commands and code that fetch (`curl`, `wget`, `gh`, `himalaya`, URLs, Python `requests`/`imaplib`), their background jobs, files they saved, Hermes' spill files, `PROMPT_FIREWALL_EXTERNAL_PATHS` | blocked at 0.38 | passed, or withheld with `ON_ERROR=closed` |
| Other tools | `delegate_task`, any tool not listed in the plugin | blocked at 0.38 | passed, or withheld with `ON_ERROR=closed` |
| First-party tools | `session_search`, `skill_view`, `tool_search`, `tool_describe`, `honcho_*` (and `PROMPT_FIREWALL_WARN_TOOLS`) | logged only | passed |
| Local content | `read_file`, `search_files`, other `terminal`/`execute_code`/`process_manage` output | blocked at 0.6 | passed, or withheld with `ON_ERROR=closed` |
| Trusted commands | `git status`, `git commit`, `mkdir`, `echo`, … (every part of the command line) | logged only | passed |
| Harness text | Hermes' approval denials, terminal hint, read-dedup notice, delegate acks; BrowserOS notes and tips; `<untrusted_tool_result>` / `[UNTRUSTED_PAGE_CONTENT]` envelopes; the plugin's own block notice | removed before scoring | passed |
| Cron script output | the body of the `## Script Output` block of a scheduled job's prompt | blocked at 0.38 | passed, or withheld with `ON_ERROR=closed` |
| Not scanned | the agent's own state and actions: `memory`, `todo_list`, `write_file`, `patch`, `send_message`, generators, UI tools; results under 3 words | | |

Images in a result are OCR'd and scanned (up to 8 per result). Images over that limit, remote image
URLs (the model provider fetches those itself), images that cannot be decoded and images whose OCR
failed are logged as `flagged` with the reason, never as `passed` (withheld with
`ON_INCOMPLETE=block`). The same goes for content hidden
with tricks like invisible Unicode or near-white image text that scores below the block threshold.
Inbound chat messages are not scanned unless `PROMPT_FIREWALL_GATEWAY=1`.
`PROMPT_FIREWALL_SKIP_TOOLS` adds tools to the not-scanned list.

## 5. Restart Hermes (**owner**)

```bash
systemctl --user restart hermes-agent      # or however Hermes runs on this machine
```

## 6. Verify

Ask the agent to fetch any web page (for example with `web_extract` on https://example.com), then:

```bash
tail -n 3 ~/.hermes/firewall/scans.jsonl
```

A working install logs `"action": "passed"` with a `"score"` for that call. What the other
outcomes mean:

| `action` | Meaning |
|---|---|
| `passed` | scanned, looked safe |
| `flagged` | passed unchanged, but worth a look: suspicious score, hidden content, a part that could not be scanned, an injection that was not blocked (warn-only, trusted commands), or a local score between 0.38 and 0.6 |
| `blocked` | injection; replaced by a stub, original in `~/.hermes/firewall/quarantine/` |
| `passed-unavailable` | scanning failed, content passed unscanned (the `error` field says why, e.g. a missing key file) |
| `passed-unscanned` | scanner paused for a minute after a failure; content passed unscanned |
| `blocked-unavailable` | scanning failed and `ON_ERROR=closed`: content withheld |
| `blocked-incomplete` | part of the result could not be scanned and `ON_INCOMPLETE=block` (the default with `ON_ERROR=closed`): content withheld, original in the quarantine |
| `passed-released` | the owner released exactly this content earlier (see below) |
| `passed-trusted` | not scanned: Hermes' own rejection of a malformed `tool_call`, recognised by rebuilding the exact message from that call's arguments. It is addressed to the model, so it would otherwise score as an injection |

A failure to reach Venice (network, key, credit, rate limit) pauses scanning for a minute
(`PROMPT_FIREWALL_BREAKER_SECONDS`), so an outage does not add a timeout to every tool call; the log
row then has `"outage": true`. A failure caused by one input (a malformed image, a page Jev refuses,
a result too long to scan within `PROMPT_FIREWALL_SCAN_DEADLINE`, 30 s) does not pause anything; it
is only logged with its own result.

The quarantine directory holds the full original of every blocked result, so treat it as
sensitive. Review it for false positives, and delete old files when you no longer need them. After
updating the plugin, restart Hermes.

**Releasing a false positive (owner only).** After reading a quarantined original and deciding it
is harmless, release exactly that content:

```bash
python3 ~/.hermes/plugins/prompt-firewall/release.py fw-20260929-2b0e42
```

The same content then passes (`passed-released`); any change to it is scanned again. This is safer
than raising a threshold or skipping a tool. Run it yourself; don't ask the agent to.

The log never contains the scanned content. To list everything that was not simply passed:

```bash
jq -r 'select(.action != "passed") | [.ts, .tool, .mode, .action, .score, ((.reasons // [])|join("; "))] | @tsv' ~/.hermes/firewall/scans.jsonl
```

## Update and uninstall

```bash
hermes plugins update prompt-firewall
hermes plugins disable prompt-firewall       # then restart Hermes; remove with: hermes plugins remove prompt-firewall
```
