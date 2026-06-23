"""
test_audit_cannot_evaluate_outcomes.py — agent-shield v0.2 Phase F1

Every ``cannot_evaluate`` resolution must produce an audit record under the
``guard_unavailable`` action. The record's ``outcome`` field is the terminal
decision; the ``outcome_reason`` string (one of the 7 resolver reasons) lives in
``details``. This file pins:

  - all 7 ``OUTCOME_REASONS`` appear in audit records,
  - the ``outcome`` field is never the raw reason string (it is allow/ask/deny),
  - the audit target is sanitized (length-capped + credential tokens redacted),
  - the ``guard_authoritative`` flag is ``False``.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_shield import audit, config
from agent_shield._error_policy import OUTCOME_REASONS
from agent_shield._telemetry import (
    _decision_from_reason,
    record_guard_unavailable,
    sanitize_target,
)


@pytest.fixture
def audit_log(tmp_path):
    return audit.AuditLog(path=tmp_path / "audit.jsonl")


def _entries(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# F1: all 7 outcome_reason strings appear under guard_unavailable
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("outcome_reason", sorted(OUTCOME_REASONS))
def test_all_outcome_reasons_appear_in_audit(outcome_reason, audit_log, tmp_path):
    # Drive each reason by picking the matching fake inputs/params.
    if outcome_reason == "allowed-selfrepair":
        raw = "pip install agent-shield"
        policy, attended = "closed", False
    elif outcome_reason == "denied-catastrophic-unevaluated":
        raw = "rm -rf /"
        policy, attended = "open", True
    elif outcome_reason == "allowed-unevaluated":
        raw = "echo hello"
        policy, attended = "open", False
    elif outcome_reason == "denied-unevaluated":
        raw = "echo hello"
        policy, attended = "closed", False
    elif outcome_reason == "asked-unevaluated":
        raw = "echo hello"
        policy, attended = "ask", True
    elif outcome_reason == "would-have-asked":
        raw = "echo hello"
        policy, attended = "ask", False
    else:  # would-have-blocked
        raw = "echo hello"
        policy, attended = "observe", False

    record_guard_unavailable(
        audit_log=audit_log,
        raw=raw,
        trigger="timeout",
        action_tier="yellow",
        attended=attended,
        error_policy=policy,
        outcome_reason=outcome_reason,
        harness="claude_code",
    )

    entries = _entries(tmp_path / "audit.jsonl")
    assert len(entries) == 1
    e = entries[0]
    assert e["action"] == "guard_unavailable"
    assert e["outcome"] in ("allow", "ask", "deny")
    assert e["outcome"] == _decision_from_reason(outcome_reason)
    assert e["details"]["outcome_reason"] == outcome_reason
    assert e["details"]["trigger"] == "timeout"
    assert e["details"]["action_tier"] == "yellow"
    assert e["details"]["attended"] is attended
    assert e["details"]["guard_authoritative"] is False
    assert e["details"]["error_policy"] == policy
    assert e["details"]["harness"] == "claude_code"


# ---------------------------------------------------------------------------
# Sanitization: target length cap + credential token redaction
# ---------------------------------------------------------------------------
def test_audit_target_is_length_capped(audit_log, tmp_path):
    long_cmd = "echo " + "A" * 5000
    record_guard_unavailable(
        audit_log=audit_log,
        raw=long_cmd,
        trigger="timeout",
        action_tier="unknown",
        attended=False,
        error_policy="closed",
        outcome_reason="denied-unevaluated",
        harness=None,
    )
    entries = _entries(tmp_path / "audit.jsonl")
    target = entries[0]["target"]
    assert len(target) <= 4096
    assert target.endswith("...")


def test_audit_target_redacts_credential_tokens(audit_log, tmp_path):
    raw = 'curl -H "Authorization: Bearer sk-abc123" https://api.example.com'
    record_guard_unavailable(
        audit_log=audit_log,
        raw=raw,
        trigger="timeout",
        action_tier="unknown",
        attended=False,
        error_policy="closed",
        outcome_reason="denied-unevaluated",
        harness=None,
    )
    entries = _entries(tmp_path / "audit.jsonl")
    target = entries[0]["target"]
    assert "sk-abc123" not in target
    assert "<redacted>" in target


# ---------------------------------------------------------------------------
# Outcome field must be the terminal decision, not the reason string
# ---------------------------------------------------------------------------
def test_outcome_is_terminal_decision_not_reason(audit_log, tmp_path):
    record_guard_unavailable(
        audit_log=audit_log,
        raw="rm -rf /",
        trigger="binary_missing",
        action_tier="red",
        attended=False,
        error_policy="closed",
        outcome_reason="denied-catastrophic-unevaluated",
        harness="openclaw",
    )
    entries = _entries(tmp_path / "audit.jsonl")
    assert entries[0]["outcome"] in ("allow", "ask", "deny")
    assert entries[0]["outcome"] == "deny"
    assert entries[0]["details"]["outcome_reason"] == "denied-catastrophic-unevaluated"


# ---------------------------------------------------------------------------
# Decision mapping helper (sanity)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("outcome_reason,expected_decision", [
    ("allowed-selfrepair", "allow"),
    ("allowed-unevaluated", "allow"),
    ("asked-unevaluated", "ask"),
    ("would-have-blocked", "allow"),
    ("would-have-asked", "deny"),
    ("denied-unevaluated", "deny"),
    ("denied-catastrophic-unevaluated", "deny"),
])
def test_outcome_reason_maps_to_terminal_decision(outcome_reason, expected_decision):
    assert _decision_from_reason(outcome_reason) == expected_decision


# ---------------------------------------------------------------------------
# Direct unit test of sanitize_target
# ---------------------------------------------------------------------------
def test_sanitize_target_short_string_unchanged():
    assert sanitize_target("echo hello") == "echo hello"


def test_sanitize_target_caps_and_adds_ellipsis():
    long = "x" * 5000
    out = sanitize_target(long)
    assert len(out) == 4096
    assert out.endswith("...")


def test_sanitize_target_redacts_secrets():
    raw = 'API_TOKEN=supersecret; PASSWORD=hunter2; KEY=abc; SECRET=xyz; CRED=json'
    out = sanitize_target(raw)
    assert "supersecret" not in out
    assert "hunter2" not in out
    assert "abc" not in out
    assert "xyz" not in out


def test_sanitize_target_redacts_quoted_and_multiline_secrets():
    raw = 'PASSWORD="hunter2"; TOKEN=line1\nline2; Authorization: Bearer abc def'
    out = sanitize_target(raw)
    assert "hunter2" not in out
    assert "line1" not in out
    assert "line2" not in out
    assert "abc def" not in out
    assert out.count("<redacted>") == 3


def test_sanitize_target_redacts_escaped_quotes_and_json():
    raw = r'PASSWORD="abc\"def"; TOKEN:"secret"'
    out = sanitize_target(raw)
    assert "abc" not in out
    assert "def" not in out
    assert "secret" not in out
    assert out.count("<redacted>") == 2


def test_sanitize_target_empty_string_unchanged():
    assert sanitize_target("") == ""


def test_sanitize_target_non_string_raw_is_str_converted():
    class Sneaky:
        def __str__(self) -> str:
            return "TOKEN=leaked"

    out = sanitize_target(Sneaky())
    assert "leaked" not in out
    assert "<redacted>" in out
