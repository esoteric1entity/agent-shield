"""OpenClaw before_tool_call adapter (functional).

Input  : an OpenClaw before_tool_call event dict
         {"toolName": str, "params": {...}, "derivedPaths"?: [str], ...}
Output : a BeforeToolCallResult dict:
           deny  -> {"block": True, "blockReason": reason}      (terminal deny)
           ask   -> {"requireApproval": {...}}                  (pause + approve)
           allow -> {}                                          (proceed)

Decision logic is the SAME neutral core the Claude Code adapter uses, so an
equivalent action yields an identical GuardResult across harnesses. Fail-open on
unparseable/unknown input, matching the Claude Code adapter's documented posture.

The thin TypeScript companion plugin (adapters/openclaw_plugin.ts) calls this via
subprocess and returns this dict from its before_tool_call handler.
"""
from __future__ import annotations

import json
import sys

from .. import bash_guard, write_guard
from .._result import GuardResult

_PATH_KEYS = ("file_path", "path", "filePath")


def _extract(event: dict) -> tuple[str | None, str | None]:
    """Return (command, path) — at most one is non-None. Best-effort, never raises."""
    params = (event or {}).get("params") or {}
    if not isinstance(params, dict):
        params = {}
    cmd = params.get("command")
    if isinstance(cmd, str):
        return cmd, None
    for key in _PATH_KEYS:
        if isinstance(params.get(key), str):
            return None, params[key]
    derived = (event or {}).get("derivedPaths")
    if isinstance(derived, list) and derived and isinstance(derived[0], str):
        return None, derived[0]
    return None, None


def decide(event: dict) -> GuardResult:
    cmd, path = _extract(event)
    if cmd is not None:
        return bash_guard.check_command(cmd)
    if path is not None:
        return write_guard.check_path(path)
    return GuardResult(decision="allow")


def format_response(result: GuardResult) -> dict:
    if result.decision == "deny":
        return {"block": True, "blockReason": result.reason}
    if result.decision == "ask":
        return {
            "requireApproval": {
                "title": "agent-shield",
                "description": result.reason,
                "severity": "warning",
                "allowedDecisions": ["allow-once", "deny"],
            }
        }
    return {}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the TS companion plugin. Reads a before_tool_call event
    JSON on stdin; writes a BeforeToolCallResult JSON to stdout. Always exit 0;
    unparseable input fails open ({} == allow) and oversize input asks, matching
    the Claude Code guards' stdin handling for cross-CLI parity."""
    _ = argv
    try:
        stream = getattr(sys.stdin, "buffer", None)
        if stream is not None:
            raw = stream.read(bash_guard._MAX_READ_BYTES + 1)
            oversize = len(raw) > bash_guard._MAX_READ_BYTES
            stdin_text = bash_guard._decode_stdin_bytes(raw)
        else:
            stdin_text = sys.stdin.read(bash_guard._MAX_READ_BYTES + 1)
            oversize = len(stdin_text) > bash_guard._MAX_READ_BYTES
        if oversize:
            result = GuardResult(decision="ask", reason="Hook input exceeds the size cap — confirm manually")
        else:
            event = json.loads(stdin_text)
            result = decide(event if isinstance(event, dict) else {})
        sys.stdout.write(json.dumps(format_response(result)))
    except Exception:  # noqa: BLE001 — guard contract: never crash
        sys.stdout.write("{}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
