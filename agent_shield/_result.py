"""Shared GuardResult dataclass for all agent-shield guards."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Decision = Literal["allow", "ask", "deny", "cannot_evaluate"]


@dataclass(frozen=True)
class GuardResult:
    """The result of a guard check.

    Attributes:
        decision: One of "allow" (silent pass), "ask" (prompt user),
            "deny" (hard block), or "cannot_evaluate" (an INTERNAL,
            pre-serialization value meaning the guard could not reach a verdict
            — e.g. a hook binary was missing or a subprocess errored). It is NOT
            a terminal decision: the error-policy resolver always maps it,
            together with ``trigger`` and the active policy, to a terminal
            allow/ask/deny before serialization. The core guard check functions
            never return it.
        reason: Human-readable explanation; empty string for "allow".
        trigger: For "cannot_evaluate" only — why evaluation failed. Intended
            value set (documentation only; not runtime-validated):
            {"binary_missing", "spawn_fail", "timeout", "nonzero_exit",
            "unparseable"}. ``None`` for terminal decisions.
        action_tier: For "cannot_evaluate" only — the severity tier the policy
            resolver should use. Intended value set (documentation only; not
            runtime-validated): {"red", "yellow", "unknown"}. ``None`` for
            terminal decisions.
    """

    decision: Decision
    reason: str = ""
    trigger: str | None = None
    action_tier: str | None = None

    def to_hook_json(self) -> dict | None:
        """Convert to Claude Code PreToolUse hook output JSON.

        Returns None for "allow" (silent pass — bash version emits no stdout).
        """
        if self.decision == "allow":
            return None
        # "cannot_evaluate" -> "deny": Claude Code only understands
        # allow/ask/deny, so the internal value maps to the deny shape. This is a
        # DOCUMENTED, NORMALLY-UNREACHABLE defensive fallback: in production the
        # error-policy resolver (a later task) always maps cannot_evaluate +
        # trigger + policy to a TERMINAL allow/ask/deny BEFORE serialization, so
        # to_hook_json should never actually receive cannot_evaluate on the live
        # path. This stays decision->shape only — no policy logic lives here.
        permission_decision = "deny" if self.decision == "cannot_evaluate" else self.decision
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission_decision,
                "permissionDecisionReason": self.reason,
            }
        }
