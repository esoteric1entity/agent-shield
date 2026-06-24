"""G4: the Claude Code adapter translates a CC PreToolUse event via the neutral core."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from agent_shield import bash_guard, write_guard
from agent_shield._result import GuardResult
from agent_shield.adapters import claude_code


def _entries(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(autouse=True)
def _clean_env_and_cache(tmp_path, monkeypatch):
    """Isolate the adapter from the real filesystem and reset its config cache."""
    home = str(tmp_path / "home")
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("USERPROFILE", home)
    for key in list(os.environ):
        if key.startswith("AGENT_SHIELD_") and key != "AGENT_SHIELD_HARNESS":
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(claude_code, "_CACHED_CFG", None)
    monkeypatch.setattr(claude_code, "_CACHED_AUDIT_LOG", None)


@pytest.fixture
def make_event():
    def _make(tool, **tool_input):
        return {"tool_name": tool, "tool_input": tool_input}

    return _make


@pytest.fixture
def fake_cfg(tmp_path):
    """Return a minimal config-like object and a temp audit log."""
    audit_path = tmp_path / "audit.jsonl"

    class Cfg:
        class guard:
            error_policy = "observe"
            unattended = False

        class audit:
            path = str(audit_path)
            retention_days = 90
            fail_mode = "open"

        compliance = "general"

    from agent_shield import audit

    return Cfg(), audit.AuditLog(path=audit_path, preset="general")


# ---------------------------------------------------------------------------
# Existing routing behavior (must remain unchanged)
# ---------------------------------------------------------------------------
def test_decide_bash_event_denies_destructive(make_event):
    event = make_event("Bash", command="rm -rf /")
    result = claude_code.decide(event)
    assert result.decision == "deny"
    assert result.reason  # non-empty


def test_decide_bash_event_allows_safe(make_event):
    event = make_event("Bash", command="ls -la /home/user")
    assert claude_code.decide(event).decision == "allow"


def test_decide_write_event_denies_self_protect(make_event):
    event = make_event("Write", file_path="/home/user/.claude/settings.json")
    assert claude_code.decide(event).decision == "deny"


def test_format_response_allow_is_none(make_event):
    event = make_event("Bash", command="ls")
    assert claude_code.format_response(claude_code.decide(event)) is None


def test_format_response_deny_is_cc_hook_json(make_event):
    event = make_event("Bash", command="rm -rf /")
    resp = claude_code.format_response(claude_code.decide(event))
    assert resp["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert resp["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert resp["hookSpecificOutput"]["permissionDecisionReason"]


def test_decide_bash_event_asks_on_yellow_tier(make_event):
    event = make_event("Bash", command="git push --force origin main")
    assert claude_code.decide(event).decision == "ask"


def test_format_response_ask_serializes(make_event):
    event = make_event("Bash", command="git push --force origin main")
    resp = claude_code.format_response(claude_code.decide(event))
    assert resp["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert resp["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("tool", ["Edit", "MultiEdit"])
def test_decide_edit_tools_route_to_write_guard(tool, make_event):
    event = make_event(tool, file_path="/home/user/.claude/settings.json")
    assert claude_code.decide(event).decision == "deny"


def test_decide_unknown_tool_is_allow(make_event):
    assert claude_code.decide(make_event("Read")).decision == "allow"


def test_decide_empty_or_none_event_is_allow():
    assert claude_code.decide({}).decision == "allow"
    assert claude_code.decide(None).decision == "allow"


# ---------------------------------------------------------------------------
# Phase D: cannot_evaluate error path
# ---------------------------------------------------------------------------
def test_bash_cannot_evaluate_closed_policy_becomes_deny(make_event, fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "closed"
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    result = claude_code.decide(make_event("Bash", command="echo hello"))
    assert result.decision == "deny"
    assert "Guard unavailable" in result.reason

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["action"] == "guard_unavailable"
    assert entries[0]["outcome"] == "deny"
    assert entries[0]["details"]["outcome_reason"] == "denied-unevaluated"
    assert entries[0]["details"]["trigger"] == "timeout"
    assert entries[0]["details"]["guard_authoritative"] is False
    assert entries[0]["details"]["harness"] == "claude_code"


def test_bash_cannot_evaluate_open_policy_becomes_allow(make_event, fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "open"
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="spawn_fail", action_tier="yellow"),
    )

    result = claude_code.decide(make_event("Bash", command="echo hello"))
    assert result.decision == "allow"
    assert result.reason == ""

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["outcome"] == "allow"
    assert entries[0]["details"]["outcome_reason"] == "allowed-unevaluated"


def test_write_cannot_evaluate_ask_attended_becomes_ask(make_event, fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "ask"
    cfg.guard.unattended = False  # attended
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        write_guard,
        "check_path",
        lambda _path: GuardResult(decision="cannot_evaluate", trigger="binary_missing", action_tier="red"),
    )

    result = claude_code.decide(make_event("Write", file_path="/tmp/note.txt"))
    assert result.decision == "ask"

    resp = claude_code.format_response(result)
    assert resp["hookSpecificOutput"]["permissionDecision"] == "ask"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["action"] == "guard_unavailable"
    assert entries[0]["outcome"] == "ask"
    assert entries[0]["details"]["outcome_reason"] == "asked-unevaluated"


def test_bash_cannot_evaluate_ask_unattended_becomes_deny(make_event, fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "ask"
    cfg.guard.unattended = True
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="nonzero_exit", action_tier="red"),
    )

    result = claude_code.decide(make_event("Bash", command="echo hello"))
    assert result.decision == "deny"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["outcome"] == "deny"
    assert entries[0]["details"]["outcome_reason"] == "would-have-asked"


# ---------------------------------------------------------------------------
# Phase D: observe visibility on would-have-blocked
# ---------------------------------------------------------------------------
def test_observe_cannot_evaluate_records_and_banners_once(make_event, fake_cfg, monkeypatch, capsys):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "observe"
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    # Reset the in-process observe state so the banner can fire.
    import agent_shield._telemetry as telem

    monkeypatch.setattr(telem, "_observe_banner_sessions", set())

    for _ in range(2):
        result = claude_code.decide(make_event("Bash", command="echo hello"))
        assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 2
    assert all(e["details"]["outcome_reason"] == "would-have-blocked" for e in entries)

    captured = capsys.readouterr()
    assert captured.err.count("would have been blocked") == 1


def test_observe_counter_is_durable(make_event, fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "observe"
    counter_path = tmp_path / "counter.json"
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )
    import agent_shield._telemetry as telem

    monkeypatch.setattr(telem, "_DEFAULT_OBSERVE_COUNTER_PATH", counter_path)
    monkeypatch.setattr(telem, "_observe_banner_sessions", set())

    for _ in range(3):
        claude_code.decide(make_event("Bash", command="echo hello"))

    data = json.loads(counter_path.read_text(encoding="utf-8"))
    # The session key is hostname-pid when no explicit session is provided.
    assert any(rec["count"] == 3 for rec in data.values())


# ---------------------------------------------------------------------------
# Phase D: catastrophic RED beats even open policy on error path
# ---------------------------------------------------------------------------
def test_bash_cannot_evaluate_catastrophic_red_beats_open(make_event, fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "open"
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    # Return cannot_evaluate but do NOT monkeypatch is_red_or_over_cap, so the
    # real RED check sees "rm -rf /" and denies.
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    result = claude_code.decide(make_event("Bash", command="rm -rf /"))
    assert result.decision == "deny"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["details"]["outcome_reason"] == "denied-catastrophic-unevaluated"


# ---------------------------------------------------------------------------
# Phase D: self-lockout allowlist beats RED on error path
# ---------------------------------------------------------------------------
def test_bash_cannot_evaluate_selfrepair_beats_red(make_event, fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "closed"
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    result = claude_code.decide(make_event("Bash", command="pip install ai-agent-shield"))
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["details"]["outcome_reason"] == "allowed-selfrepair"


# ---------------------------------------------------------------------------
# Phase D: normal-path audit records
# ---------------------------------------------------------------------------
def test_normal_bash_allow_is_recorded(make_event, fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))

    result = claude_code.decide(make_event("Bash", command="ls -la"))
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["action"] == "bash"
    assert entries[0]["outcome"] == "allow"


def test_normal_bash_deny_is_recorded(make_event, fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))

    result = claude_code.decide(make_event("Bash", command="rm -rf /"))
    assert result.decision == "deny"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["action"] == "bash"
    assert entries[0]["outcome"] == "deny"
    assert "reason" in entries[0]["details"]


def test_normal_write_with_content_uses_record_write(make_event, fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))

    result = claude_code.decide(
        make_event("Write", file_path=str(tmp_path / "out.txt"), content="hello world")
    )
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["action"] == "write"
    assert entries[0]["outcome"] == "allow"
    assert entries[0]["content_sha256_after"] is not None
    assert entries[0].get("content_sha256_before") is None


# ---------------------------------------------------------------------------
# Phase D: audit failure must not break the hook response
# ---------------------------------------------------------------------------
def test_bash_cannot_evaluate_audit_failure_still_returns_terminal(make_event, fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "closed"
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )
    # Make the audit log fail-closed and unwritable so record() raises.
    audit_log.fail_mode = "closed"
    audit_log.path = Path("/nonexistent/path/audit.jsonl")

    result = claude_code.decide(make_event("Bash", command="echo hello"))
    assert result.decision == "deny"


def test_normal_path_audit_failure_still_returns_result(make_event, fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(claude_code, "_get_config_and_log", lambda: (cfg, audit_log))
    audit_log.fail_mode = "closed"
    audit_log.path = Path("/nonexistent/path/audit.jsonl")

    result = claude_code.decide(make_event("Bash", command="ls -la"))
    assert result.decision == "allow"
