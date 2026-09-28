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
files, text read from images) is sent to Venice for scoring. If that is not acceptable, use the
local service instead (see the README).

Scoring uses Jev through Venice's Decisions API. On the benchmark corpus it cost about $0.035 per
1,000 scans; long pages are split into several requests and cost more. Create a
**dedicated** key in the Venice dashboard; a spending cap is a good idea. The rate limit is per
key (100 requests a minute on the key tested), and a long page uses several requests, so sharing
the agent's own key would slow both. The owner writes the key into a file containing only the key:

```bash
umask 077; cat > ~/.venice-firewall-key       # paste the key, press Enter, then Ctrl-D
```

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

Files read with `read_file` or `search_files` block at a higher score (0.6, `PROMPT_FIREWALL_LOCAL_FILE_BLOCK`) than everything else (0.38). A file on the agent's own disk is far less likely to hold an attack than a web page or an email, and the agent's own notes (task lists, "next: do X") are what score just above 0.38 in practice. On the benchmark this costs 4.3 points of recall (84.2% instead of 88.5% of attacks) and cuts benign blocks from 2.8% to 1.0%. The looser level also covers a web page the agent saved to disk and then reads back. Set the variable to 0.38 to use one level everywhere. Scores between the two levels are logged as `flagged`.

Scanning failures (no Venice credit, Venice down, a bug) **fail open** by default: content passes
through unscanned so the agent keeps working, and the log records it. Content already found to be
an injection is blocked even if a later part of the same result fails to scan. For strict setups,
`PROMPT_FIREWALL_ON_ERROR=closed` withholds every scanned source when scanning fails, except local
shell output. Every setting is listed in `hermes-plugin/prompt-firewall/plugin.yaml`.

### What gets scanned

| Source | Examples | On injection | When scanning fails |
|---|---|---|---|
| External content | `web_*`, `x_search`, `browser_*`, `mcp_*`, `vision_analyze`, `computer_use`, shell commands that fetch (`curl`, `wget`, `himalaya`, URLs) and their background jobs | blocked | passed, or withheld with `ON_ERROR=closed` |
| Local content and unknown tools | `read_file`, `search_files`, `delegate_task`, `session_search`, any tool not listed in the plugin | blocked | passed, or withheld with `ON_ERROR=closed` |
| Local shell output | `terminal`, `execute_code`, `process_manage` for local commands | logged only | passed |
| Cron script output | the body of the `## Script Output` block of a scheduled job's prompt | blocked | passed, or withheld with `ON_ERROR=closed` |
| Not scanned | the agent's own state and actions: `memory`, `todo_list`, `write_file`, `patch`, `send_message`, generators, UI tools; results under 3 words | | |

Images in a result are OCR'd and scanned (up to 8 per result). Images over that limit, remote image
URLs (the model provider fetches those itself), images that cannot be decoded and images whose OCR
failed are logged as `flagged` with the reason, never as `passed`. The same goes for content hidden
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
| `flagged` | passed unchanged, but worth a look: suspicious score, hidden content, a part that could not be scanned, or an injection that was not blocked (warn-only, local shell output) |
| `blocked` | injection; replaced by a stub, original in `~/.hermes/firewall/quarantine/` |
| `passed-unavailable` | scanning failed, content passed unscanned (the `error` field says why, e.g. a missing key file) |
| `passed-unscanned` | scanner paused for a minute after a failure; content passed unscanned |
| `blocked-unavailable` | scanning failed and `ON_ERROR=closed`: content withheld |
| `passed-trusted` | not scanned: Hermes' own rejection of a malformed `tool_call`, recognised by rebuilding the exact message from that call's arguments. It is addressed to the model, so it would otherwise score as an injection |

A failure to reach Venice pauses scanning for a minute (`PROMPT_FIREWALL_BREAKER_SECONDS`), so an
outage does not add a timeout to every tool call. A malformed image does not pause anything; it is
only logged with its own result.

The quarantine directory holds the full original of every blocked result, so treat it as
sensitive. Review it for false positives, and delete old files when you no longer need them. After
updating the plugin, restart Hermes.

The log never contains the scanned content. To list everything that was not simply passed:

```bash
jq -r 'select(.action != "passed") | [.ts, .tool, .action, .score, (.reasons|join("; "))] | @tsv' ~/.hermes/firewall/scans.jsonl
```

## Update and uninstall

```bash
hermes plugins update prompt-firewall
hermes plugins disable prompt-firewall       # then restart Hermes; remove with: hermes plugins remove prompt-firewall
```
