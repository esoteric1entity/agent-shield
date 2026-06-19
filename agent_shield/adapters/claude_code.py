"""Claude Code PreToolUse adapter (live).

Input  : a parsed CC PreToolUse event dict
         {"tool_name": "Bash"|"Write"|"Edit"|"MultiEdit", "tool_input": {...}}
Output : a CC hook-response dict (or None == silent allow).

Both this adapter and adapters/openclaw.py call the SAME neutral core, so an
equivalent action yields an identical GuardResult regardless of harness.
"""
from __future__ import annotations

from .. import bash_guard, write_guard
from .._result import GuardResult

_WRITE_TOOLS = {"Write", "Edit", "MultiEdit"}


def decide(event: dict) -> GuardResult:
    """Route a CC event to the neutral core. Unknown/missing -> allow (fail-open,
    matching the shipped hook contract: input that cannot be evaluated proceeds)."""
    tool = (event or {}).get("tool_name")
    tool_input = (event or {}).get("tool_input") or {}
    if tool == "Bash":
        cmd = tool_input.get("command")
        return bash_guard.check_command(cmd if isinstance(cmd, str) else "")
    if tool in _WRITE_TOOLS:
        path = tool_input.get("file_path")
        return write_guard.check_path(path if isinstance(path, str) else "")
    return GuardResult(decision="allow")


def format_response(result: GuardResult) -> dict | None:
    """CC PreToolUse response. None == silent allow (no stdout)."""
    return result.to_hook_json()
