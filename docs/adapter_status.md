# Adapter status

agent-shield has one harness-neutral decision core; harness coupling lives in thin
adapters. Decision-equivalence across adapters is asserted by
`tests/test_adapter_equivalence.py`.

| Harness | Adapter | Status | Notes |
|---|---|---|---|
| Claude Code | `agent_shield/adapters/claude_code.py` | **Live** | PreToolUse hook. CI-verified; a live Claude Code enforcement smoke test is a required pre-tag release gate (procedure provided in the repo). |
| OpenClaw / Hermes | `agent_shield/adapters/openclaw.py` + `openclaw_plugin.ts` | **Live (gateway-gated)** | `before_tool_call` hook. Enforcement requires an OpenClaw gateway that *awaits* the hook promise (post the early-2026 fire-and-forget fix); see the gateway-version note below. |
| Others (Codex / Gemini / Copilot / OpenCode) | — | Roadmap (demand-gated) | Each needs its authoritative pre-exec hook contract pulled before its adapter is built. |

**Invoking the OpenClaw adapter.** It runs either via the `agent-shield-openclaw-guard`
console script — a `before_tool_call` event JSON in on stdin, a `BeforeToolCallResult` JSON
out, which is what the TypeScript companion plugin (`openclaw_plugin.ts`) spawns — or as a
module: `python -m agent_shield.adapters.openclaw`.

**Minimum OpenClaw gateway version — pending live verification.** The concrete minimum will
be published here once agent-shield's `before_tool_call` block has been confirmed *honored*
against a live OpenClaw gateway. Until then, treat OpenClaw enforcement as *requires a recent,
hook-awaiting gateway*: the adapter and the shared decision core are functional and covered by
`tests/test_adapter_openclaw.py` and the cross-adapter equivalence test — what awaits
verification is the gateway honoring the returned block, not the adapter's decision logic.
