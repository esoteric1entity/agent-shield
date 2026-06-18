"""Shared GuardResult dataclass for all agent-shield guards."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Decision = Literal["allow", "ask", "deny"]


@dataclass(frozen=True)
class GuardResult:
    """The result of a guard check.

    Attributes:
        decision: One of "allow" (silent pass), "ask" (prompt user), "deny" (hard block).
        reason: Human-readable explanation; empty string for "allow".
    """

    decision: Decision
    reason: str = ""

    def to_hook_json(self) -> dict | None:
        """Convert to Claude Code PreToolUse hook output JSON.

        Returns None for "allow" (silent pass — bash version emits no stdout).
        """
        if self.decision == "allow":
            return None
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": self.decision,
                "permissionDecisionReason": self.reason,
            }
        }
