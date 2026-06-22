// agent-shield — thin OpenClaw companion plugin.
//
// Author: esoteric1entity, assisted by Claude Code & OpenClaw.
//
// Bridges OpenClaw's before_tool_call hook to the agent-shield Python core via the
// `agent-shield-openclaw-guard` CLI. All decision logic lives in Python (one neutral
// core shared with the Claude Code adapter); this file only marshals JSON in/out.
//
// Registers through the OpenClaw plugin-SDK entry contract — definePluginEntry +
// register(api) + api.on("before_tool_call", ...) — the export shape current OpenClaw
// gateways load (the loader looks for register/activate, not a bare `hooks` export).
// The handler's return value is the BeforeToolCallResult:
//   { block: true, blockReason }   -> terminal deny  (loader blocks on result.block === true)
//   { requireApproval: {...} }     -> pause + request approval (ask)
//   {}                             -> allow
//
// Posture: fail-open on bridge error (returns {} == allow), matching the Claude Code
// adapter. Requires an OpenClaw gateway that AWAITS the before_tool_call hook
// (see docs/adapter_status.md). Timeout is in milliseconds.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { spawnSync } from "node:child_process";

export default definePluginEntry({
  id: "agent-shield",
  register(api) {
    api.on(
      "before_tool_call",
      (event: unknown): Record<string, unknown> => {
        const proc = spawnSync("agent-shield-openclaw-guard", [], {
          input: JSON.stringify(event),
          encoding: "utf-8",
          timeout: 5000, // 5000ms (5s) — Node spawnSync expects milliseconds
        });
        if (proc.status !== 0 || !proc.stdout) {
          return {}; // fail-open (allow) — same posture as the CC adapter
        }
        try {
          return JSON.parse(proc.stdout) as Record<string, unknown>;
        } catch {
          return {};
        }
      },
      { priority: 100 },
    );
  },
});
