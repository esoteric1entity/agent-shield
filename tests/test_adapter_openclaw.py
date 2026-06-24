"""G4: the OpenClaw adapter maps the neutral core -> BeforeToolCallResult."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from agent_shield import audit, bash_guard, write_guard
from agent_shield._result import GuardResult
from agent_shield.adapters import openclaw


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
    monkeypatch.setattr(openclaw, "_CACHED_CFG", None)
    monkeypatch.setattr(openclaw, "_CACHED_AUDIT_LOG", None)
    import agent_shield._telemetry as telem

    monkeypatch.setattr(telem, "_observe_banner_sessions", set())
    monkeypatch.setattr(telem, "_observe_warned", False)


@pytest.fixture
def fake_cfg(tmp_path):
    """Return a minimal config-like object and a temp audit log."""
    audit_path = tmp_path / "audit.jsonl"

    class Cfg:
        class guard:
            error_policy = "closed"
            unattended = False

        class audit:
            path = str(audit_path)
            retention_days = 90
            fail_mode = "open"

        compliance = "general"

    return Cfg(), audit.AuditLog(path=audit_path, preset="general")


def _bash_event(cmd: str, **extra) -> dict:
    return {"toolName": "bash", "params": {"command": cmd}, **extra}


def _write_event(path: str, **extra) -> dict:
    params = {"file_path": path}
    params.update(extra)
    return {"toolName": "write_file", "params": params}


# ---------------------------------------------------------------------------
# Existing routing behavior (must remain unchanged)
# ---------------------------------------------------------------------------
def test_decide_command_denies_destructive():
    assert openclaw.decide(_bash_event("rm -rf /")).decision == "deny"


def test_decide_command_allows_safe():
    assert openclaw.decide(_bash_event("ls -la")).decision == "allow"


def test_decide_path_from_derived_paths():
    event = {"toolName": "write_file", "params": {}, "derivedPaths": ["/home/user/.claude/settings.json"]}
    assert openclaw.decide(event).decision == "deny"


def test_extract_non_dict_params_does_not_raise():
    # "params" is truthy but not a dict — _extract must fail open, not raise.
    assert openclaw._extract({"params": "not-a-dict"}) == (None, None)
    assert openclaw._extract({"params": ["x"]}) == (None, None)


def test_decide_non_dict_params_allows():
    assert openclaw.decide({"toolName": "Bash", "params": "x"}).decision == "allow"


def test_decide_command_asks_on_yellow_tier():
    assert openclaw.decide(_bash_event("git push --force origin main")).decision == "ask"


def test_decide_empty_event_is_allow():
    assert openclaw.decide({}).decision == "allow"
    assert openclaw.decide(None).decision == "allow"


def test_format_deny_is_terminal_block():
    resp = openclaw.format_response(GuardResult("deny", "destructive command"))
    assert resp == {"block": True, "blockReason": "destructive command"}


def test_format_ask_is_require_approval():
    resp = openclaw.format_response(GuardResult("ask", "confirm this"))
    approval = resp["requireApproval"]
    assert approval["description"] == "confirm this"
    assert approval["severity"] == "warning"
    assert approval["allowedDecisions"] == ["allow-once", "deny"]


def test_format_allow_is_empty():
    assert openclaw.format_response(GuardResult("allow", "")) == {}


def test_main_reads_event_and_emits_block(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash_event("rm -rf /"))))
    rc = openclaw.main([])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["block"] is True


def test_main_unparseable_is_allow(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("not json{{"))
    rc = openclaw.main([])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {}


def test_main_oversize_input_asks(monkeypatch, capsys):
    huge = "x" * (bash_guard._MAX_READ_BYTES + 1)
    monkeypatch.setattr("sys.stdin", io.StringIO(huge))
    rc = openclaw.main([])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "requireApproval" in out  # oversize -> conservative ask, not a trusted parse


def test_main_normal_event_still_allows(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(json.dumps({"toolName": "bash", "params": {"command": "ls -la"}}))
    )
    rc = openclaw.main([])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {}


def test_main_uses_stdin_buffer_when_available(monkeypatch, capsys):
    """Exercise the bytes-buffer branch that the TS plugin actually uses."""
    payload = json.dumps(_bash_event("rm -rf /")).encode("utf-8")

    class FakeStdin:
        buffer = io.BytesIO(payload)

    monkeypatch.setattr("sys.stdin", FakeStdin())
    rc = openclaw.main([])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["block"] is True


# ---------------------------------------------------------------------------
# Phase C: cannot_evaluate error path (bash)
# ---------------------------------------------------------------------------
def test_bash_cannot_evaluate_closed_default_becomes_deny(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    result = openclaw.decide(_bash_event("echo hello"))
    assert result.decision == "deny"
    assert "Guard unavailable" in result.reason

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["action"] == "guard_unavailable"
    assert entries[0]["outcome"] == "deny"
    assert entries[0]["details"]["outcome_reason"] == "denied-unevaluated"
    assert entries[0]["details"]["trigger"] == "timeout"
    assert entries[0]["details"]["guard_authoritative"] is False
    assert entries[0]["details"]["harness"] == "openclaw"


def test_bash_cannot_evaluate_open_policy_becomes_allow(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "open"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="spawn_fail", action_tier="yellow"),
    )

    result = openclaw.decide(_bash_event("echo hello"))
    assert result.decision == "allow"
    assert result.reason == ""

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["outcome"] == "allow"
    assert entries[0]["details"]["outcome_reason"] == "allowed-unevaluated"
    assert entries[0]["details"]["harness"] == "openclaw"


def test_bash_cannot_evaluate_ask_attended_becomes_ask(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "ask"
    cfg.guard.unattended = False  # attended
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="binary_missing", action_tier="red"),
    )

    result = openclaw.decide(_bash_event("echo hello"))
    assert result.decision == "ask"

    resp = openclaw.format_response(result)
    assert resp["requireApproval"]["description"]

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["action"] == "guard_unavailable"
    assert entries[0]["outcome"] == "ask"
    assert entries[0]["details"]["outcome_reason"] == "asked-unevaluated"


def test_bash_cannot_evaluate_ask_unattended_becomes_deny(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "ask"
    cfg.guard.unattended = True
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="nonzero_exit", action_tier="red"),
    )

    result = openclaw.decide(_bash_event("echo hello"))
    assert result.decision == "deny"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["outcome"] == "deny"
    assert entries[0]["details"]["outcome_reason"] == "would-have-asked"


# ---------------------------------------------------------------------------
# Phase C: cannot_evaluate error path (write)
# ---------------------------------------------------------------------------
def test_write_cannot_evaluate_closed_default_becomes_deny(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        write_guard,
        "check_path",
        lambda _path: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    result = openclaw.decide(_write_event("/tmp/note.txt"))
    assert result.decision == "deny"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["action"] == "guard_unavailable"
    assert entries[0]["outcome"] == "deny"
    assert entries[0]["details"]["outcome_reason"] == "denied-unevaluated"
    assert entries[0]["details"]["harness"] == "openclaw"


def test_write_cannot_evaluate_open_policy_becomes_allow(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "open"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        write_guard,
        "check_path",
        lambda _path: GuardResult(decision="cannot_evaluate", trigger="spawn_fail", action_tier="yellow"),
    )

    result = openclaw.decide(_write_event("/tmp/note.txt"))
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["outcome"] == "allow"


def test_write_cannot_evaluate_ask_attended_becomes_ask(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "ask"
    cfg.guard.unattended = False
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        write_guard,
        "check_path",
        lambda _path: GuardResult(decision="cannot_evaluate", trigger="binary_missing", action_tier="red"),
    )

    result = openclaw.decide(_write_event("/tmp/note.txt"))
    assert result.decision == "ask"


def test_write_cannot_evaluate_ask_unattended_becomes_deny(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "ask"
    cfg.guard.unattended = True
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        write_guard,
        "check_path",
        lambda _path: GuardResult(decision="cannot_evaluate", trigger="nonzero_exit", action_tier="red"),
    )

    result = openclaw.decide(_write_event("/tmp/note.txt"))
    assert result.decision == "deny"


# ---------------------------------------------------------------------------
# Phase C: observe visibility on would-have-blocked
# ---------------------------------------------------------------------------
def test_observe_cannot_evaluate_banners_once_per_sessionid(fake_cfg, monkeypatch, capfd):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "observe"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    for _ in range(2):
        result = openclaw.decide(_bash_event("echo hello", sessionId="sess-openclaw-1"))
        assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 2
    assert all(e["details"]["outcome_reason"] == "would-have-blocked" for e in entries)

    captured = capfd.readouterr()
    assert captured.err.count("would have been blocked") == 1


def test_observe_cannot_evaluate_without_sessionid_fires_banner(fake_cfg, monkeypatch, capfd):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "observe"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    result = openclaw.decide(_bash_event("echo hello"))
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["details"]["outcome_reason"] == "would-have-blocked"

    captured = capfd.readouterr()
    assert captured.err.count("would have been blocked") == 1


def test_observe_extracts_sessionid_from_event(fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "observe"
    counter_path = tmp_path / "observe-counter.json"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    import agent_shield._telemetry as telem

    monkeypatch.setattr(telem, "_DEFAULT_OBSERVE_COUNTER_PATH", counter_path)
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    openclaw.decide(_bash_event("echo hello", sessionId="sess-openclaw-1"))
    data = json.loads(counter_path.read_text(encoding="utf-8"))
    assert any("sess-openclaw-1" in key for key in data)


def test_observe_falls_back_to_hostname_pid_when_sessionid_missing(fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "observe"
    counter_path = tmp_path / "observe-counter.json"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    import agent_shield._telemetry as telem

    monkeypatch.setattr(telem, "_DEFAULT_OBSERVE_COUNTER_PATH", counter_path)
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    openclaw.decide(_bash_event("echo hello"))
    data = json.loads(counter_path.read_text(encoding="utf-8"))
    # Fallback key is hostname + pid-group; it should not contain a session id.
    assert not any("sess-" in key for key in data)
    assert len(data) == 1


# ---------------------------------------------------------------------------
# Phase C: catastrophic RED beats even open policy on error path
# ---------------------------------------------------------------------------
def test_bash_cannot_evaluate_catastrophic_red_beats_open(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "open"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    # Return cannot_evaluate but do NOT monkeypatch is_red_or_over_cap, so the
    # real RED check sees "rm -rf /" and denies.
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    result = openclaw.decide(_bash_event("rm -rf /"))
    assert result.decision == "deny"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["details"]["outcome_reason"] == "denied-catastrophic-unevaluated"


def test_write_cannot_evaluate_catastrophic_red_beats_open(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "open"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        write_guard,
        "check_path",
        lambda _path: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    result = openclaw.decide(_write_event("/home/user/.claude/settings.json"))
    assert result.decision == "deny"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["details"]["outcome_reason"] == "denied-catastrophic-unevaluated"


# ---------------------------------------------------------------------------
# Phase C: self-lockout allowlist beats RED on error path
# ---------------------------------------------------------------------------
def test_bash_cannot_evaluate_selfrepair_beats_red(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "closed"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    result = openclaw.decide(_bash_event("pip install ai-agent-shield"))
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["details"]["outcome_reason"] == "allowed-selfrepair"


def test_write_cannot_evaluate_selfrepair_beats_red(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "closed"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        write_guard,
        "check_path",
        lambda _path: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )

    # Use /opt/agent-shield/ prefix so the test does not depend on the HOME
    # env var (the self-lockout allowlist computes its prefixes at import time).
    result = openclaw.decide(_write_event("/opt/agent-shield/config.toml"))
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert entries[0]["details"]["outcome_reason"] == "allowed-selfrepair"


# ---------------------------------------------------------------------------
# Phase C: normal-path audit records
# ---------------------------------------------------------------------------
def test_normal_bash_allow_is_recorded(fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))

    result = openclaw.decide(_bash_event("ls -la"))
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["action"] == "bash"
    assert entries[0]["outcome"] == "allow"


def test_normal_bash_deny_is_recorded(fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))

    result = openclaw.decide(_bash_event("rm -rf /"))
    assert result.decision == "deny"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["action"] == "bash"
    assert entries[0]["outcome"] == "deny"
    assert "reason" in entries[0]["details"]


def test_normal_write_with_content_uses_record_write(fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))

    result = openclaw.decide(_write_event(str(tmp_path / "out.txt"), content="hello world"))
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["action"] == "write"
    assert entries[0]["outcome"] == "allow"
    assert entries[0]["content_sha256_after"] is not None
    assert entries[0].get("content_sha256_before") is None


def test_normal_write_without_content_uses_plain_write_record(fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))

    result = openclaw.decide(_write_event(str(tmp_path / "out.txt")))
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["action"] == "write"
    assert entries[0]["outcome"] == "allow"
    assert "content_sha256_after" not in entries[0]
    assert "content_sha256_before" not in entries[0]


def test_normal_write_with_content_before_and_after_hashes_both(fake_cfg, monkeypatch, tmp_path):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))

    result = openclaw.decide(
        _write_event(str(tmp_path / "out.txt"), content_before="old", content_after="new")
    )
    assert result.decision == "allow"

    entries = _entries(Path(cfg.audit.path))
    assert len(entries) == 1
    assert entries[0]["content_sha256_before"] is not None
    assert entries[0]["content_sha256_after"] is not None


# ---------------------------------------------------------------------------
# Phase C: audit failure must not break the hook response
# ---------------------------------------------------------------------------
def _make_append_raise(audit_log, monkeypatch):
    """Force the audit log write to fail in a platform-agnostic way."""
    def _raise(_fields):
        raise audit.AuditWriteError("forced audit failure")

    audit_log.fail_mode = "closed"
    monkeypatch.setattr(audit_log, "_append", _raise)


def test_bash_cannot_evaluate_audit_failure_still_returns_terminal(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "closed"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )
    _make_append_raise(audit_log, monkeypatch)

    result = openclaw.decide(_bash_event("echo hello"))
    assert result.decision == "deny"


def test_normal_path_audit_failure_still_returns_result(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    _make_append_raise(audit_log, monkeypatch)

    result = openclaw.decide(_bash_event("ls -la"))
    assert result.decision == "allow"


def test_write_normal_path_audit_failure_still_returns_result(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    _make_append_raise(audit_log, monkeypatch)

    result = openclaw.decide(_write_event("/tmp/note.txt"))
    assert result.decision == "allow"


# ---------------------------------------------------------------------------
# Phase C: CLI path for cannot_evaluate
# ---------------------------------------------------------------------------
def test_main_cannot_evaluate_closed_emits_block(fake_cfg, monkeypatch, capsys):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash_event("echo hello"))))

    rc = openclaw.main([])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["block"] is True


def test_main_cannot_evaluate_open_emits_empty(fake_cfg, monkeypatch, capsys):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "open"
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash_event("echo hello"))))

    rc = openclaw.main([])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {}


def test_main_cannot_evaluate_ask_emits_require_approval(fake_cfg, monkeypatch, capsys):
    cfg, audit_log = fake_cfg
    cfg.guard.error_policy = "ask"
    cfg.guard.unattended = False
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash_event("echo hello"))))

    rc = openclaw.main([])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "requireApproval" in out


# ---------------------------------------------------------------------------
# Phase C: defense-in-depth post-condition
# ---------------------------------------------------------------------------
def test_decide_defensively_coerces_leaked_cannot_evaluate(fake_cfg, monkeypatch):
    cfg, audit_log = fake_cfg
    monkeypatch.setattr(openclaw, "_get_config_and_log", lambda: (cfg, audit_log))
    monkeypatch.setattr(
        bash_guard,
        "check_command",
        lambda _cmd: GuardResult(decision="cannot_evaluate", trigger="timeout", action_tier="red"),
    )
    # Force the resolver to leak the non-terminal decision.
    monkeypatch.setattr(
        openclaw,
        "_resolve_cannot_evaluate",
        lambda _tool, _raw, _result, _event: GuardResult(decision="cannot_evaluate"),
    )

    result = openclaw.decide(_bash_event("echo hello"))
    assert result.decision == "deny"
    assert "internal error" in result.reason.lower()
