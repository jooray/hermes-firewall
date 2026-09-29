# How prompt-firewall hooks into Hermes Agent

Written against hermes-agent `866cd752b5`. File and line references may drift in later versions.

## Where untrusted content can be intercepted

**Before context** means the hook runs before the content reaches the model's context.

| Point | Where | Before context | Can modify | On failure | Covers |
|---|---|---|---|---|---|
| `tool_execution` middleware (**used**) | `hermes_cli/middleware.py:143` (`run_tool_execution_middleware`), wired in `agent/tool_executor.py` | yes | yes, any return value | no host timeout. An exception raised after `next_call` returns the **raw** result, so the plugin catches everything itself | every tool the agent loop dispatches: registry tools, MCP, inline tools, `delegate_task` |
| `transform_tool_result` hook | `model_tools.py` (`_apply_transform_tool_result_hook`), `agent/inline_tool_executors.py:61` | yes | yes (first `str` returned) | bounded by `plugins.hook_callback_timeout` (30 s). A timeout or exception passes the unscanned result, and the callback is then suppressed for 60 s | same set, except timeouts and cancellations |
| `llm_request` middleware (**used**, backstop) | `agent/turn_api_request.py:143` (`apply_llm_request_middleware`) | yes, the last point before the provider call | yes | exception: request passes unchanged | everything in the outgoing request, including cron script output pasted into the prompt. Runs on every call, so verdicts are cached |
| `pre_gateway_dispatch` hook (**optional**) | `gateway/run_inbound.py:111` | yes | skip or rewrite `event.text` | exception: message allowed | inbound chat text. Off by default, because chat is usually the owner |
| `pre_tool_call` hook | `model_tools.py` | n/a (runs before the tool) | block or change args | fails closed | URL and domain policy only; it never sees content |

Within one tool call, the order is: `tool_request` middleware → `pre_tool_call` → **`tool_execution` middleware wraps dispatch** → `post_tool_call` → `transform_tool_result` → spill of large results → **subdirectory context appended** → result committed → next `llm_request`. The scan finishes before the result is appended to the transcript, so the session database and memory never store a blocked payload. What Hermes adds after the middleware (the subdirectory context below) is never scanned.

## Why middleware rather than `transform_tool_result`

`transform_tool_result` is time-bounded. A slow callback is abandoned and the original result is used; the same callback is then skipped for 60 s. That is fine for fail-open behaviour, but it can't guarantee a block. `tool_execution` middleware runs synchronously with no host timeout, so the plugin decides what happens on failure. It still counts against the tool's own deadline.

## Plugin API used

- Discovery: `~/.hermes/plugins/<name>/` with `plugin.yaml` and an `__init__.py` exposing `register(ctx)`. The plugin loads only when listed in `plugins.enabled` (`hermes plugins enable prompt-firewall`), after a restart.
- `ctx.register_middleware("tool_execution" | "llm_request", cb)` and `ctx.register_hook("pre_gateway_dispatch", cb)`. Callback kwargs are passed by name, so the callbacks accept `**kwargs`. `next_call(args)` is single-use.
- The plugin is imported as a package (`submodule_search_locations` is the plugin directory), so relative imports work. That is how `core/` is vendored.
- Settings: `ctx.get_config(key)` reads `plugins.entries.prompt-firewall.settings.<key>` from the active profile's `config.yaml` (`hermes_cli/plugins.py`, `PluginContext.get_config`); the keys are declared in `plugin.yaml`'s `config_schema`. The plugin reads them on every call, falling back to its `PROMPT_FIREWALL_*` environment variables.
- Paths: `hermes_constants.get_hermes_home()` is resolved on every call, so under a multi-profile gateway the scan log, quarantine and release list follow the active profile rather than the one the process started with. Checked with the real `PluginContext` and `set_hermes_home_override` switching A → B → A.
- Middleware kwargs include `session_id` and `tool_call_id` (`agent/inline_tool_executors.py:tool_hook_ids`); they go into the scan log.

## Gaps (not covered without Hermes changes)

- **Auxiliary LLM inputs**: vision descriptions, the compression summariser, and MCP sampling go to helper models the plugin never sees. The descriptions they return are scanned when they come back as tool results.
- **Inbound images and voice**: the gateway enriches these straight into the user message. Only the `llm_request` backstop could see them, and it scans only cron output by default.
- **`post_tool_call` observers** see raw results, but nothing they see reaches the model.
- **Subdirectory context files**: when a tool call touches a directory for the first time, Hermes appends that directory's `AGENTS.md`/`CLAUDE.md`/`.cursorrules` to the tool result (`agent/tool_executor.py:1115-1121`, `agent/subdirectory_hints.py`, text starting `[Subdirectory context discovered: …]`). That happens after the middleware returns, so the plugin never sees it; only Hermes' own regex scan (`agent/prompt_builder.py:_scan_context_content`) runs on it. Scanning it with Jev would not help anyway: these files are instructions addressed to an AI by design and score as injections. The real question is whether the repository is trusted. For untrusted checkouts, run the agent with context files off (`skip_context_files`), and ask upstream for provenance on appended parts.
- **Shell output**: judged by where the content comes from. Commands and code that fetch (`curl`, `wget`, `gh`, mail and Nostr CLIs, URLs, Python network and mail libraries) are external. Files such a command writes (`-o`, `-O`, `-P`, `>`, `tee`) are remembered in memory and are external when read later, and so is a background job started by such a command when its output is read through `process_manage`. The ids and paths are forgotten when Hermes restarts. Other shell output is local: it is blocked at the local level (0.6), not only logged. Only commands that report on the agent's own work (`git status`, `mkdir`, ...) are log-only. A fetch the patterns do not recognise is treated as local content, not trusted.
- **Spill files**: large results are written to `$HERMES_HOME/cache/spillover` and read back in pieces with `read_file`. The whole result was scanned before it was spilled, but a piece can score higher on its own, so reads from that directory count as external.
- **Cron context**: the backstop scans the `## Script Output` and `## Script Error` blocks. It finds a block's end by the closing code fence Hermes adds, not by the next heading, so a heading inside the output cannot cut the scan short. Output of other jobs pulled in through `context_from` is not scanned. The hook handles Chat Completions and Anthropic `messages` and Responses `input` payloads, with string or list content.

Upstream changes that would close these gaps: a `transform_inbound_message` hook after gateway enrichment, a `transform_cron_context` hook in `cron/scheduler_prompt.py`, a hook after subdirectory-context enrichment that says which part of the result each piece of text came from, and a fail-closed option for `transform_tool_result`.
