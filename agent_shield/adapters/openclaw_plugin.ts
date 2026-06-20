// agent-shield — thin OpenClaw companion plugin.
//
// Bridges OpenClaw's before_tool_call hook to the agent-shield Python core via the
// `agent-shield-openclaw-guard` CLI. All decision logic lives in Python (one neutral
// core shared with the Claude Code adapter); this file only marshals JSON in/out.
//
// Returns a BeforeToolCallResult:
//   { block: true, blockReason }            -> terminal deny
//   { requireApproval: {...} }              -> pause + request approval (ask)
//   {}                                      -> allow
//
// Posture: fail-open on bridge error (returns {} == allow), matching the Claude Code
// adapter. Requires a recent OpenClaw gateway that AWAITS the before_tool_call promise
// (see docs/adapter_status.md). Timeout is in milliseconds.
import { spawnSync } from "node:child_process";

export const hooks = {
  before_tool_call: {
    priority: 100,
    handler: (event: unknown): Record<string, unknown> => {
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
  },
};
