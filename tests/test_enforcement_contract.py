"""G1 (CI half): a mock harness event -> adapter -> asserted response JSON.
Proves the enforcement code path end-to-end on every CI OS. The LIVE half
(harness actually fires the hook + honors deny) is a manual pre-tag smoke test —
see scratch/enforcement-test/."""
import json

from agent_shield.adapters import claude_code, openclaw


def test_cc_denies_destructive_with_reason():
    event = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
    resp = claude_code.format_response(claude_code.decide(event))
    block = resp["hookSpecificOutput"]
    assert block["permissionDecision"] == "deny"
    assert block["permissionDecisionReason"]
    assert json.dumps(resp).isascii()  # ASCII-safe on any console codepage


def test_cc_allows_safe_is_silent():
    event = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
    assert claude_code.format_response(claude_code.decide(event)) is None


def test_openclaw_denies_destructive_terminal_block():
    event = {"toolName": "bash", "params": {"command": "rm -rf /"}}
    resp = openclaw.format_response(openclaw.decide(event))
    assert resp["block"] is True and resp["blockReason"]


def test_openclaw_allows_safe_is_empty():
    event = {"toolName": "bash", "params": {"command": "ls -la"}}
    assert openclaw.format_response(openclaw.decide(event)) == {}
