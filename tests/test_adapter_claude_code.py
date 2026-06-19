"""G4: the Claude Code adapter translates a CC PreToolUse event via the neutral core."""
import pytest
from agent_shield.adapters import claude_code


def test_decide_bash_event_denies_destructive():
    event = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
    result = claude_code.decide(event)
    assert result.decision == "deny"
    assert result.reason  # non-empty


def test_decide_bash_event_allows_safe():
    event = {"tool_name": "Bash", "tool_input": {"command": "ls -la /home/user"}}
    assert claude_code.decide(event).decision == "allow"


def test_decide_write_event_denies_self_protect():
    event = {"tool_name": "Write", "tool_input": {"file_path": "/home/user/.claude/settings.json"}}
    assert claude_code.decide(event).decision == "deny"


def test_format_response_allow_is_none():
    event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
    assert claude_code.format_response(claude_code.decide(event)) is None


def test_format_response_deny_is_cc_hook_json():
    event = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
    resp = claude_code.format_response(claude_code.decide(event))
    assert resp["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert resp["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert resp["hookSpecificOutput"]["permissionDecisionReason"]


def test_decide_bash_event_asks_on_yellow_tier():
    event = {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}}
    assert claude_code.decide(event).decision == "ask"


def test_format_response_ask_serializes():
    event = {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}}
    resp = claude_code.format_response(claude_code.decide(event))
    assert resp["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert resp["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("tool", ["Edit", "MultiEdit"])
def test_decide_edit_tools_route_to_write_guard(tool):
    event = {"tool_name": tool, "tool_input": {"file_path": "/home/user/.claude/settings.json"}}
    assert claude_code.decide(event).decision == "deny"


def test_decide_unknown_tool_is_allow():
    assert claude_code.decide({"tool_name": "Read", "tool_input": {}}).decision == "allow"


def test_decide_empty_or_none_event_is_allow():
    assert claude_code.decide({}).decision == "allow"
    assert claude_code.decide(None).decision == "allow"
