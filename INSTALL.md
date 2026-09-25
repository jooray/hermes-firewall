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

## 2. OCR for images (optional, **owner**: needs sudo)

On macOS, Apple Vision is used automatically and nothing needs installing. Elsewhere, install
Tesseract:

| System | Command |
|---|---|
| Arch | `sudo pacman -S tesseract tesseract-data-eng` |
| Debian / Ubuntu | `sudo apt install tesseract-ocr` |
| Fedora | `sudo dnf install tesseract` |

Check with `tesseract --version`. Without OCR, image metadata is still scanned and every image with
possible text is marked suspicious. Images take roughly 0.5 s each on a laptop and ~10 s on a small
Celeron-class server; text scans don't use OCR.

## 3. Venice API key (**owner**)

Scoring uses Jev through Venice's Decisions API, which costs about $0.035 per 1,000 scans. Create a
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

`WARN_ONLY=1` never blocks. Suspicious content reaches the model inside an "untrusted data"
banner. Keep it on for about a week, check the scan log, then remove the line to start blocking.

Scanning failures (no Venice credit, Venice down, a bug) **fail open** by default: content passes
through unscanned and the agent keeps working, and the log records it. For strict setups,
`PROMPT_FIREWALL_ON_ERROR=closed` withholds web, MCP and email content instead. Every setting is
listed in `hermes-plugin/prompt-firewall/plugin.yaml`.

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
| `banner` | suspicious or injection; passed with an "untrusted data" banner (warn-only or hidden content) |
| `blocked` | injection; replaced by a stub, original in `~/.hermes/firewall/quarantine/` |
| `passed-unavailable` | scanning failed, content passed (the `error` field says why, e.g. a missing key file) |
| `passed-unscanned` | scanner paused for a minute after a failure |

The log never contains the scanned content. To list everything that was not simply passed:

```bash
jq -r 'select(.action != "passed") | [.ts, .tool, .action, .score, (.reasons|join("; "))] | @tsv' ~/.hermes/firewall/scans.jsonl
```

## Update and uninstall

```bash
hermes plugins update prompt-firewall
hermes plugins disable prompt-firewall       # then restart Hermes; remove with: hermes plugins remove prompt-firewall
```
