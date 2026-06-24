"""
test_observe_visibility.py — agent-shield v0.2 Phase F4

Every ``would-have-blocked`` observe resolution gets an audit record PLUS extra
visibility: a per-session stderr banner on the first occurrence and a durable
per-session counter. This file pins:

  - audit record is written with outcome="allow" and outcome_reason="would-have-blocked",
  - counter increments per call for the same session,
  - one-line stderr banner fires once per session (but again for a new session),
  - corrupted counter JSON resets gracefully instead of crashing,
  - empty/None session falls back to hostname+PID,
  - unwritable counter directory emits a single stderr warning and degrades.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from agent_shield import audit
from agent_shield._telemetry import (
    observe_visibility_hook,
    record_guard_unavailable,
)


def _entries(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(autouse=True)
def _reset_observe_state(monkeypatch):
    """Isolate per-session banner/counter state between tests."""
    import agent_shield._telemetry as telem

    monkeypatch.setattr(telem, "_observe_banner_sessions", set())
    monkeypatch.setattr(telem, "_observe_warned", False)


@pytest.fixture
def audit_log(tmp_path):
    return audit.AuditLog(path=tmp_path / "audit.jsonl")


# -----------------------------------------------------------------------------
# F4: audit record shape for observe visibility
# -----------------------------------------------------------------------------
def test_observe_records_guard_unavailable(audit_log, tmp_path):
    counter_path = tmp_path / "counter.json"
    observe_visibility_hook(
        audit_log=audit_log,
        raw="rm -rf /",
        trigger="timeout",
        action_tier="red",
        attended=False,
        error_policy="observe",
        harness="claude_code",
        session="sess-observe-1",
        counter_path=counter_path,
    )
    entries = _entries(tmp_path / "audit.jsonl")
    assert len(entries) == 1
    e = entries[0]
    assert e["action"] == "guard_unavailable"
    assert e["outcome"] == "allow"
    assert e["details"]["outcome_reason"] == "would-have-blocked"
    assert e["details"]["guard_authoritative"] is False
    assert e["details"]["trigger"] == "timeout"
    assert e["details"]["action_tier"] == "red"
    assert e["details"]["attended"] is False
    assert e["details"]["error_policy"] == "observe"
    assert e["details"]["harness"] == "claude_code"


# -----------------------------------------------------------------------------
# Counter behavior
# -----------------------------------------------------------------------------
def test_counter_increments_per_session(audit_log, tmp_path):
    counter_path = tmp_path / "counter.json"
    for _ in range(3):
        observe_visibility_hook(
            audit_log=audit_log,
            raw="rm -rf /",
            trigger="timeout",
            action_tier="red",
            attended=False,
            error_policy="observe",
            harness="claude_code",
            session="sess-inc",
            counter_path=counter_path,
        )
    data = json.loads(counter_path.read_text(encoding="utf-8"))
    rec = data["sess-inc"]
    assert rec["count"] == 3
    assert "first_seen_ts" in rec
    assert "last_seen_ts" in rec
    assert rec["last_seen_ts"] >= rec["first_seen_ts"]


def test_corrupted_counter_resets_gracefully(audit_log, tmp_path):
    counter_path = tmp_path / "counter.json"
    counter_path.write_text("this is not json", encoding="utf-8")
    observe_visibility_hook(
        audit_log=audit_log,
        raw="rm -rf /",
        trigger="timeout",
        action_tier="red",
        attended=False,
        error_policy="observe",
        harness="claude_code",
        session="sess-corrupt",
        counter_path=counter_path,
    )
    data = json.loads(counter_path.read_text(encoding="utf-8"))
    assert data["sess-corrupt"]["count"] == 1


def test_none_session_falls_back_to_hostname_and_pid(audit_log, tmp_path, monkeypatch):
    counter_path = tmp_path / "counter.json"
    monkeypatch.setattr(socket, "gethostname", lambda: "testhost-f4")
    monkeypatch.setattr(os, "getpid", lambda: 424242)
    observe_visibility_hook(
        audit_log=audit_log,
        raw="rm -rf /",
        trigger="timeout",
        action_tier="red",
        attended=False,
        error_policy="observe",
        harness="claude_code",
        session=None,
        counter_path=counter_path,
    )
    data = json.loads(counter_path.read_text(encoding="utf-8"))
    assert "testhost-f4-424242" in data


# -----------------------------------------------------------------------------
# Banner behavior
# -----------------------------------------------------------------------------
def test_banner_fires_once_per_session(audit_log, tmp_path, capsys):
    counter_path = tmp_path / "counter.json"
    for _ in range(2):
        observe_visibility_hook(
            audit_log=audit_log,
            raw="rm -rf /",
            trigger="timeout",
            action_tier="red",
            attended=False,
            error_policy="observe",
            harness="claude_code",
            session="sess-banner-once",
            counter_path=counter_path,
        )
    captured = capsys.readouterr()
    assert captured.err.count("would have been blocked") == 1
    assert "audit log" in captured.err


def test_banner_fires_again_for_different_session(audit_log, tmp_path, capsys):
    counter_path = tmp_path / "counter.json"
    sessions = ("sess-a", "sess-b")
    for session in sessions:
        observe_visibility_hook(
            audit_log=audit_log,
            raw="rm -rf /",
            trigger="timeout",
            action_tier="red",
            attended=False,
            error_policy="observe",
            harness="claude_code",
            session=session,
            counter_path=counter_path,
        )
    captured = capsys.readouterr()
    assert captured.err.count("would have been blocked") == 2


# -----------------------------------------------------------------------------
# Degradation: unwritable counter directory emits one warning
# -----------------------------------------------------------------------------
def test_unwritable_counter_emits_one_warning(audit_log, tmp_path, capsys):
    # Create a file where the counter's parent directory should be, so mkdir fails.
    not_a_dir = tmp_path / "not_a_dir"
    not_a_dir.write_text("x", encoding="utf-8")
    counter_path = not_a_dir / "counter.json"

    for _ in range(2):
        observe_visibility_hook(
            audit_log=audit_log,
            raw="rm -rf /",
            trigger="timeout",
            action_tier="red",
            attended=False,
            error_policy="observe",
            harness="claude_code",
            session="sess-unwritable",
            counter_path=counter_path,
        )

    captured = capsys.readouterr()
    assert captured.err.count("observe counter unavailable") == 1
    # The audit record is still written despite the counter failure.
    entries = _entries(tmp_path / "audit.jsonl")
    assert len(entries) == 2


# -----------------------------------------------------------------------------
# Guard against accidentally importing the private helper as public API
# -----------------------------------------------------------------------------
def test_observe_uses_record_guard_unavailable_underneath(audit_log, tmp_path):
    # record_guard_unavailable is the F1 primitive; observe_visibility_hook is a
    # thin wrapper around it. This is a smoke test, not a structural assertion.
    counter_path = tmp_path / "counter.json"
    entry = observe_visibility_hook(
        audit_log=audit_log,
        raw="rm -rf /",
        trigger="timeout",
        action_tier="red",
        attended=False,
        error_policy="observe",
        harness="claude_code",
        session="sess-smoke",
        counter_path=counter_path,
    )
    assert entry is not None
    assert entry["outcome"] == "allow"
