"""
test_result_cannot_evaluate.py — the 4th typed decision value
=============================================================

Tests for the ``cannot_evaluate`` decision introduced into the neutral core
(``agent_shield/_result.py``) for v0.2 error-path fail-closed handling.

``cannot_evaluate`` is an INTERNAL, pre-serialization decision: the error-policy
resolver (a later task) always maps it — together with its ``trigger`` and the
active policy — to a TERMINAL allow/ask/deny BEFORE serialization. It must never
be returned by the core guard check functions, and if it ever reaches
``to_hook_json()`` (a documented, normally-unreachable defensive fallback) it
maps to the Claude Code DENY shape, because Claude Code only understands
allow/ask/deny.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

from agent_shield import bash_guard, write_guard
from agent_shield._result import GuardResult


# ============================================================
# Construction + field round-trip
# ============================================================

def test_cannot_evaluate_constructs_with_trigger_and_action_tier():
    """A cannot_evaluate result carries trigger + action_tier metadata."""
    result = GuardResult(
        decision="cannot_evaluate",
        trigger="binary_missing",
        action_tier="red",
    )
    assert result.decision == "cannot_evaluate"
    assert result.trigger == "binary_missing"
    assert result.action_tier == "red"


def test_trigger_and_action_tier_default_to_none():
    """Existing call sites construct GuardResult without the new fields."""
    result = GuardResult(decision="allow")
    assert result.trigger is None
    assert result.action_tier is None


# ============================================================
# to_hook_json: cannot_evaluate maps to the DENY shape
# ============================================================

def test_cannot_evaluate_to_hook_json_maps_to_deny_shape():
    """Claude Code only understands allow/ask/deny — cannot_evaluate -> deny.

    The literal string "cannot_evaluate" must NOT leak into permissionDecision.
    """
    result = GuardResult(
        decision="cannot_evaluate",
        reason="binary missing",
        trigger="binary_missing",
        action_tier="red",
    )
    hook_json = result.to_hook_json()
    assert hook_json is not None
    out = hook_json["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "deny"
    assert out["permissionDecision"] != "cannot_evaluate"
    assert out["permissionDecisionReason"] == "binary missing"


# ============================================================
# REGRESSION PINS — existing decision -> shape mappings unchanged
# ============================================================

def test_allow_to_hook_json_is_none_unchanged():
    """REGRESSION PIN: allow -> None (silent pass), byte-identical to v0.1."""
    assert GuardResult(decision="allow").to_hook_json() is None


def test_deny_to_hook_json_shape_unchanged():
    """REGRESSION PIN: a plain deny produces the existing deny shape."""
    result = GuardResult(decision="deny", reason="x")
    assert result.to_hook_json() == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "x",
        }
    }


# ============================================================
# GUARD-LEVEL PIN — core checks never return cannot_evaluate
# ============================================================

# Representative inputs: a clearly-benign command/path (allow) AND a clearly
# dangerous one that the core denies. The core check functions are pure tier
# classifiers; only a later adapter/CLI error-boundary task ever sets
# cannot_evaluate.
_BASH_CASES = (
    "ls -la /home/user",   # benign -> allow
    "rm -rf /",            # dangerous -> deny
)
_WRITE_CASES = (
    "/home/user/projects/myapp/main.py",   # benign -> allow
    "/home/user/.claude/settings.json",    # dangerous -> deny
)


def test_bash_guard_core_never_returns_cannot_evaluate():
    """bash_guard.check_command never produces the internal cannot_evaluate."""
    for cmd in _BASH_CASES:
        result = bash_guard.check_command(cmd)
        assert result.decision != "cannot_evaluate", (
            f"check_command({cmd!r}) leaked cannot_evaluate"
        )


def test_write_guard_core_never_returns_cannot_evaluate():
    """write_guard.check_path never produces the internal cannot_evaluate."""
    for path in _WRITE_CASES:
        result = write_guard.check_path(path)
        assert result.decision != "cannot_evaluate", (
            f"check_path({path!r}) leaked cannot_evaluate"
        )
