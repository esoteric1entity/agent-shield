# Adapter status

agent-shield has one harness-neutral decision core; harness coupling lives in thin
adapters. Decision-equivalence across adapters is asserted by
`tests/test_adapter_equivalence.py`.

| Harness | Adapter | Status | Notes |
|---|---|---|---|
| Claude Code | `agent_shield/adapters/claude_code.py` | **Live** | PreToolUse hook. CI-verified; a live Claude Code enforcement smoke test is a required pre-tag release gate (procedure provided in the repo). |
| OpenClaw / Hermes | `agent_shield/adapters/openclaw.py` + `openclaw_plugin/` | **Live-verified — OpenClaw 2026.4.26** | `before_tool_call` hook via the plugin-SDK `register()` entry. Live enforcement confirmed 2026-06-20 (deny blocked + allow passed + disable/re-enable control); requires a gateway that *awaits* the hook (2026.4.26 does). See the verification + install notes below. |
| Others (Codex / Gemini / Copilot / OpenCode) | — | Roadmap (demand-gated) | Each needs its authoritative pre-exec hook contract pulled before its adapter is built. |

**Invoking the OpenClaw adapter.** It runs either via the `agent-shield-openclaw-guard`
console script — a `before_tool_call` event JSON in on stdin, a `BeforeToolCallResult` JSON
out, which is what the TypeScript companion plugin (`openclaw_plugin/index.ts`) spawns — or as a
module: `python -m agent_shield.adapters.openclaw`.

**All console scripts.** The package installs five: `agent-shield-bash-guard`, `agent-shield-write-guard`, `agent-shield-vet`, `agent-shield-openclaw-guard`, and `agent-shield-plugin` — for harness hooks, direct CLI use, and Claude Code settings management.

**Where the plugin lives after install.** The companion plugin ships inside the installed package as a ready-to-install directory at `<site-packages>/agent_shield/adapters/openclaw_plugin/` (`index.ts` + `openclaw.plugin.json` + `package.json`). Locate it with: `python -c "import agent_shield, pathlib; print(pathlib.Path(agent_shield.__file__).parent / 'adapters' / 'openclaw_plugin')"`.

**Live enforcement — VERIFIED on OpenClaw 2026.4.26 (be8c246), 2026-06-20.** A live agent's
guarded write was **blocked** with the verbatim guard reason ("Cannot modify Claude
settings.json (contains hook/permission configs)"; file not created), a safe write **passed**,
and a disable/re-enable **control** confirmed the block is agent-shield's. The gateway awaits
`before_tool_call` and honors `result.block === true` + `blockReason`/`requireApproval`
(confirmed against OpenClaw's plugin-SDK). **Minimum gateway version: 2026.4.26** (the verified
floor; earlier hook-awaiting gateways are likely fine). Evidence + raw artifacts:
`Claude_Logs/live-test-evidence/` in the workspace.

**Installing the OpenClaw plugin (verified recipe).** The package **ships the plugin as a
ready-to-install directory** — `agent_shield/adapters/openclaw_plugin/` with `index.ts` plus the
two manifests OpenClaw needs — so nothing has to be hand-authored. Locate the installed directory
and install it directly:

```sh
DIR=$(python -c "import agent_shield, pathlib; print(pathlib.Path(agent_shield.__file__).parent / 'adapters' / 'openclaw_plugin')")
openclaw plugins install "$DIR" --dangerously-force-unsafe-install   # the spawnSync bridge trips the shell-exec scanner
```

Then **fully restart the gateway** — SIGUSR1 hot-reload updates `plugins list` but does **not**
re-register plugin hooks.

The shipped directory contains:
- `index.ts` — the companion plugin. It **must** register through the plugin-SDK entry contract
  (`export default definePluginEntry({ id, register(api) { api.on("before_tool_call", handler, { priority }) } })`).
  The legacy bare `export const hooks = {...}` shape is **silently skipped** by current loaders
  (`missing register/activate export`) → no enforcement. `tests/test_openclaw_plugin_shape.py`
  pins this shape so the no-op cannot regress.
- `openclaw.plugin.json` — `{ "id": "agent-shield", "name": "agent-shield", "enabledByDefault": true, "configSchema": { "type": "object", "additionalProperties": false, "properties": {} } }`
- `package.json` — `{ "name": "agent-shield", "version": "0.2.0", "type": "module", "openclaw": { "extensions": ["./index.ts"] } }` — the `openclaw.extensions` key is **required** (without it the install falls back to the hook-pack path and errors on a missing `HOOK.md`).

The adapter and shared core are covered by `tests/test_adapter_openclaw.py` + the cross-adapter
equivalence test; the directory install contract above by `tests/test_openclaw_plugin_shape.py`.

**Error-policy posture.** Bridge errors (missing/erroring guard) are routed through the
neutral error-policy resolver (`agent_shield/_error_policy.py`). The default `error_policy`
is harness-aware: `closed` for OpenClaw and `observe` for Claude Code, so a bridge failure
in the OpenClaw adapter denies by default. This default can be overridden via the
`AGENT_SHIELD_ERROR_POLICY` environment variable or the `guard.error_policy` config key; a
tightening compliance preset (`healthcare`/`biotech`) forces it to `closed` above all tiers.
