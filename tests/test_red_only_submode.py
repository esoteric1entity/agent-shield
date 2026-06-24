"""
test_red_only_submode.py — RED single-source sub-mode (``--red-only``)
======================================================================

v0.2 task B2. The guards expose a single-sourced, descriptive ``pattern_id``
per RED pattern (the RED table is the ONE source of truth — no codegen, no
drift), a library-level ``is_red()`` helper that reuses that table, and a
``--red-only`` CLI sub-mode that emits ``{"red": bool, "pattern_id": str}``.

The existing stdin-hook behaviour and the RED/YELLOW/GREEN decisions of
``check_command`` / ``check_path`` are UNCHANGED by the 3-tuple refactor —
the regression pins below hold that line.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import io
import json

import pytest

from agent_shield import bash_guard, write_guard

# A path the write-guard RED table denies (matches ``\.claude/settings\.json$``).
_RED_PATH = "~/.claude/settings.json"
_BENIGN_PATH = "/tmp/scratch.log"


# ============================================================
# is_red() — library helper, reuses the RED table (first-match-wins)
# ============================================================


def test_bash_is_red_true_carries_pattern_id():
    red, pattern_id = bash_guard.is_red("rm -rf /")
    assert red is True
    assert isinstance(pattern_id, str)
    assert pattern_id != ""


def test_bash_is_red_false_for_benign():
    assert bash_guard.is_red("ls -la") == (False, "")


def test_write_is_red_true_carries_pattern_id():
    red, pattern_id = write_guard.is_red(_RED_PATH)
    assert red is True
    assert isinstance(pattern_id, str)
    assert pattern_id != ""


def test_write_is_red_false_for_benign():
    assert write_guard.is_red(_BENIGN_PATH) == (False, "")


# ============================================================
# pattern_id is single-sourced — every RED entry carries a descriptive,
# non-empty, snake_case slug that is NOT the full reason and NOT an index.
# ============================================================


def _assert_ids(red_table):
    ids = [entry[2] for entry in red_table]
    reasons = [entry[1] for entry in red_table]
    assert len(ids) == len(red_table)
    for pid, reason in zip(ids, reasons):
        assert isinstance(pid, str) and pid != "", f"empty pattern_id: {pid!r}"
        # descriptive slug, not the reason text, not a bare integer index
        assert pid != reason
        assert not pid.isdigit()
        assert pid == pid.lower()
        assert " " not in pid
    return ids


def test_bash_red_table_is_3tuple_with_ids():
    for entry in bash_guard._RED_PATTERNS:
        assert len(entry) == 3
    _assert_ids(bash_guard._RED_PATTERNS)


def test_write_red_table_is_3tuple_with_ids():
    for entry in write_guard._RED_PATTERNS:
        assert len(entry) == 3
    _assert_ids(write_guard._RED_PATTERNS)


# ============================================================
# --red-only CLI sub-mode: prints {"red": ..., "pattern_id": ...}; exit 0;
# the existing stdin-hook path is not touched.
# ============================================================


def _run_red_only(module, argv, monkeypatch, capsys):
    # Guard against the sub-mode ever falling through to the stdin read.
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    rc = module.main(argv)
    out = capsys.readouterr().out
    return rc, out


def test_bash_red_only_true(monkeypatch, capsys):
    rc, out = _run_red_only(bash_guard, ["--red-only", "rm -rf /"], monkeypatch, capsys)
    assert rc == 0
    payload = json.loads(out)
    assert payload["red"] is True
    assert payload["pattern_id"] != ""


def test_bash_red_only_false(monkeypatch, capsys):
    rc, out = _run_red_only(bash_guard, ["--red-only", "ls -la"], monkeypatch, capsys)
    assert rc == 0
    payload = json.loads(out)
    assert payload["red"] is False
    assert payload["pattern_id"] == ""


def test_write_red_only_true(monkeypatch, capsys):
    rc, out = _run_red_only(write_guard, ["--red-only", _RED_PATH], monkeypatch, capsys)
    assert rc == 0
    payload = json.loads(out)
    assert payload["red"] is True
    assert payload["pattern_id"] != ""


def test_write_red_only_false(monkeypatch, capsys):
    rc, out = _run_red_only(write_guard, ["--red-only", _BENIGN_PATH], monkeypatch, capsys)
    assert rc == 0
    payload = json.loads(out)
    assert payload["red"] is False
    assert payload["pattern_id"] == ""


# ============================================================
# REGRESSION PINS — the 3-tuple refactor must not change any decision
# or any reason string of check_command / check_path.
# ============================================================


def test_check_command_unchanged_by_refactor():
    deny = bash_guard.check_command("rm -rf /")
    assert deny.decision == "deny"
    assert deny.reason == "Destructive rm -rf targeting root directory"
    assert bash_guard.check_command("ls -la").decision == "allow"


def test_check_path_unchanged_by_refactor():
    deny = write_guard.check_path(_RED_PATH)
    assert deny.decision == "deny"
    assert deny.reason == (
        "Cannot modify Claude settings.json (contains hook/permission configs)"
    )
    assert write_guard.check_path(_BENIGN_PATH).decision == "allow"


def test_is_red_pattern_id_matches_red_table_first_match():
    # is_red must return the id of the SAME entry check_command denies on.
    red, pid = bash_guard.is_red("rm -rf /")
    assert red is True
    table_ids = [e[2] for e in bash_guard._RED_PATTERNS]
    assert pid in table_ids


@pytest.mark.parametrize(
    "argv",
    [["rm -rf /"], [], ["--red-only"]],  # no flag / empty / flag with no positional
)
def test_red_only_absent_or_incomplete_does_not_crash(argv, monkeypatch, capsys):
    # No --red-only positional -> must not raise; the never-crash contract holds.
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert bash_guard.main(argv) == 0
    assert write_guard.main(argv) == 0


def test_is_red_over_cap_input_is_not_red():
    """``is_red()`` is a THIN RED-only probe: input longer than the guard's size
    cap returns ``(False, "")`` (the size cap is a ``check_command`` /
    ``check_path`` concern). Pinned so the documented divergence from the full
    guards stays intentional and stable. NOT a downgrade on any live path: the
    hook runs ``check_command`` (a terminal ``ask`` for over-cap input), so
    ``is_red`` — wired as the resolver's ``red_check`` — is never reached for an
    over-cap command. (See the F3 carried-finding: F3 decides whether the
    error-path RED override should treat over-cap as RED-by-default.)"""
    huge_cmd = "rm -rf / " + ("A" * (bash_guard._MAX_INPUT_CHARS + 1))
    assert len(huge_cmd) > bash_guard._MAX_INPUT_CHARS
    assert bash_guard.is_red(huge_cmd) == (False, "")
    huge_path = _RED_PATH + ("A" * (write_guard._MAX_INPUT_CHARS + 1))
    assert write_guard.is_red(huge_path) == (False, "")


def test_red_only_cli_skips_dash_leading_positional(monkeypatch, capsys):
    """KNOWN, BENIGN probe-fidelity limitation (pinned for stability): the
    ``--red-only`` CLI takes the first NON-dash token as the positional, so a
    literal command/path that itself starts with ``-`` is skipped and reported
    not-red — identical to passing no positional. This affects ONLY the
    documented CI/library probe; real RED commands/paths do not start with
    ``-``, and the security-critical in-process ``is_red()`` (what F3 wires)
    evaluates the raw string directly with no token-skipping."""
    rc, out = _run_red_only(bash_guard, ["--red-only", "-weird-token"], monkeypatch, capsys)
    assert rc == 0
    assert json.loads(out) == {"red": False, "pattern_id": ""}
    rc, out = _run_red_only(write_guard, ["--red-only", "-weird-token"], monkeypatch, capsys)
    assert rc == 0
    assert json.loads(out) == {"red": False, "pattern_id": ""}
