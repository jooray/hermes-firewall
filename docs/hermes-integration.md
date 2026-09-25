# How prompt-firewall hooks into Hermes Agent

Written against hermes-agent `fe675c503d`. File and line references may drift in later versions.

## Where untrusted content can be intercepted

**Before context** means the hook runs before the content reaches the model's context.

| Point | Where | Before context | Can modify | On failure | Covers |
|---|---|---|---|---|---|
| `tool_execution` middleware (**used**) | `hermes_cli/middleware.py:138-213`, wired in `agent/tool_executor.py` | yes | yes, any return value | no host timeout. An exception raised after `next_call` returns the **raw** result, so the plugin catches everything itself | every tool the agent loop dispatches: registry tools, MCP, inline tools, `delegate_task` |
| `transform_tool_result` hook | `model_tools.py:843-860`, `agent/inline_tool_executors.py:61-80` | yes | yes (first `str` returned) | bounded by `plugins.hook_callback_timeout` (30 s). A timeout or exception passes the unscanned result, and the callback is then suppressed for 60 s | same set, except timeouts and cancellations |
| `llm_request` middleware (**used**, backstop) | `agent/turn_api_request.py:140-152` | yes, the last point before the provider call | yes | exception: request passes unchanged | everything in the outgoing request, including cron script output pasted into the prompt. Runs on every call, so verdicts are cached |
| `pre_gateway_dispatch` hook (**optional**) | `gateway/run_inbound.py:67-102` | yes | skip or rewrite `event.text` | exception: message allowed | inbound chat text. Off by default, because chat is usually the owner |
| `pre_tool_call` hook | `model_tools.py:760-790` | n/a (runs before the tool) | block or change args | fails closed | URL and domain policy only; it never sees content |

Within one tool call, the order is: `tool_request` middleware → `pre_tool_call` → **`tool_execution` middleware wraps dispatch** → `post_tool_call` → `transform_tool_result` → result committed → next `llm_request`. The scan finishes before the result is appended to the transcript, so the session database and memory never store a blocked payload.

## Why middleware rather than `transform_tool_result`

`transform_tool_result` is time-bounded. A slow callback is abandoned and the original result is used; the same callback is then skipped for 60 s. That is fine for fail-open behaviour, but it can't guarantee a block. `tool_execution` middleware runs synchronously with no host timeout, so the plugin decides what happens on failure. It still counts against the tool's own deadline.

## Plugin API used

- Discovery: `~/.hermes/plugins/<name>/` with `plugin.yaml` and an `__init__.py` exposing `register(ctx)`. The plugin loads only when listed in `plugins.enabled` (`hermes plugins enable prompt-firewall`), after a restart.
- `ctx.register_middleware("tool_execution" | "llm_request", cb)` and `ctx.register_hook("pre_gateway_dispatch", cb)`. Callback kwargs are passed by name, so the callbacks accept `**kwargs`. `next_call(args)` is single-use.
- The plugin is imported as a package (`submodule_search_locations` is the plugin directory), so relative imports work. That is how `core/` is vendored.
- Configuration comes from environment variables (`~/.hermes/.env`); there is no generic plugin-settings accessor.

## Gaps (not covered without Hermes changes)

- **Auxiliary LLM inputs**: vision descriptions, the compression summariser, and MCP sampling go to helper models the plugin never sees. The descriptions they return are scanned when they come back as tool results.
- **Inbound images and voice**: the gateway enriches these straight into the user message. Only the `llm_request` backstop could see them, and it scans only cron output by default.
- **`post_tool_call` observers** see raw results, but nothing they see reaches the model.
- **Shell output**: commands that fetch outside content (`curl`, `wget`, mail and Nostr CLIs, URLs) are scanned and fail closed if configured. Other shell output is scanned in warn-only mode, because it is mostly the agent's own build and CLI output.

Upstream changes that would close these gaps: a `transform_inbound_message` hook after gateway enrichment, a `transform_cron_context` hook in `cron/scheduler_prompt.py`, and a fail-closed option for `transform_tool_result`.
