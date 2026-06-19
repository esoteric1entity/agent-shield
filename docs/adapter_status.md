# Adapter status

agent-shield has one harness-neutral decision core; harness coupling lives in thin
adapters. Decision-equivalence across adapters is asserted by
`tests/test_adapter_equivalence.py`.

| Harness | Adapter | Status | Notes |
|---|---|---|---|
| Claude Code | `agent_shield/adapters/claude_code.py` | **Live** | PreToolUse hook; verified by CI + a live enforcement smoke test. |
| OpenClaw / Hermes | `agent_shield/adapters/openclaw.py` + `openclaw_plugin.ts` | **Live (gateway-gated)** | `before_tool_call` hook. Enforcement requires an OpenClaw gateway that AWAITS the hook promise (post the early-2026 fire-and-forget fix). Verify with the live OpenClaw enforcement test; record the minimum gateway version below. |
| Others (Codex / Gemini / Copilot / OpenCode) | — | Roadmap (demand-gated) | Each needs its authoritative pre-exec hook contract pulled before its adapter is built. |

**Minimum OpenClaw gateway version:** _to be filled from the live enforcement test_ (see `scratch/enforcement-test/RUN_OPENCLAW.md`).
