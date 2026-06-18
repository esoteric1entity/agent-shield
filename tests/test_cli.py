"""
test_cli.py — CLI contract tests for ``python -m agent_shield.{bash,write}_guard``
==================================================================================

Audit findings #2 + #5 (pre-launch quality audit): the advertised
contract is "always exit 0; decision via stdout JSON (empty stdout = allow)".
Pre-fix, malformed stdin (top-level list/null/number, non-string command,
UTF-8-BOM/UTF-16 bytes) raised uncaught exceptions -> exit 1 + traceback.
For a PreToolUse guard, a crash means the dangerous call is never evaluated —
a silent bypass. These tests pin the contract via real subprocess calls,
which is exactly the surface a hook harness exercises.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

PKG_ROOT = Path(__file__).resolve().parent.parent


def _run_guard(module: str, stdin_bytes: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", f"agent_shield.{module}"],
        input=stdin_bytes,
        capture_output=True,
        cwd=PKG_ROOT,
        timeout=30,
    )


def _assert_contract(proc: subprocess.CompletedProcess, expect_decision: str | None):
    """expect_decision None means: allow (empty stdout). Always: exit 0, no traceback."""
    assert proc.returncode == 0, (
        f"guard exited {proc.returncode} (contract: always 0)\nstderr: {proc.stderr.decode(errors='replace')[:500]}"
    )
    assert b"Traceback" not in proc.stderr, proc.stderr.decode(errors="replace")[:500]
    stdout = proc.stdout.decode("utf-8", errors="replace").strip()
    if expect_decision is None:
        assert stdout == "", f"expected silent allow, got: {stdout[:200]}"
    else:
        payload = json.loads(stdout)
        assert payload["hookSpecificOutput"]["permissionDecision"] == expect_decision


# ============================================================
# Well-formed inputs — the happy-path contract
# ============================================================


def test_bash_guard_cli_deny():
    proc = _run_guard("bash_guard", b'{"tool_input":{"command":"rm -rf /"}}')
    _assert_contract(proc, "deny")


def test_bash_guard_cli_allow_is_silent():
    proc = _run_guard("bash_guard", b'{"tool_input":{"command":"ls -la"}}')
    _assert_contract(proc, None)


def test_write_guard_cli_deny():
    proc = _run_guard("write_guard", b'{"tool_input":{"file_path":"/h/.claude/settings.json"}}')
    _assert_contract(proc, "deny")


def test_write_guard_cli_allow_is_silent():
    proc = _run_guard("write_guard", b'{"tool_input":{"file_path":"/tmp/scratch.log"}}')
    _assert_contract(proc, None)


# ============================================================
# Audit #2 — malformed stdin must NOT crash (exit 0, silent)
# ============================================================

MALFORMED_INPUTS = [
    b"",                                          # empty stdin
    b"not json at all",                           # unparseable
    b"null",                                      # JSON null top-level
    b"[1, 2, 3]",                                 # JSON list top-level
    b"42",                                        # JSON number top-level
    b'"just a string"',                           # JSON string top-level
    b'{"tool_input": null}',                      # null tool_input
    b'{"tool_input": [1]}',                       # list tool_input
    b'{"tool_input": "x"}',                       # string tool_input
    b'{"tool_input": {"command": 123}}',          # non-string command
    b'{"tool_input": {"command": ["rm"]}}',       # list command
    b'{"tool_input": {"command": null}}',         # null command
    b'{"tool_input": {"file_path": {"a": 1}}}',   # dict file_path
    b'{"tool_input": {"file_path": 3.14}}',       # float file_path
]


@pytest.mark.parametrize("stdin_bytes", MALFORMED_INPUTS, ids=lambda b: repr(b[:30]))
def test_bash_guard_cli_malformed_never_crashes(stdin_bytes: bytes):
    _assert_contract(_run_guard("bash_guard", stdin_bytes), None)


@pytest.mark.parametrize("stdin_bytes", MALFORMED_INPUTS, ids=lambda b: repr(b[:30]))
def test_write_guard_cli_malformed_never_crashes(stdin_bytes: bytes):
    _assert_contract(_run_guard("write_guard", stdin_bytes), None)


# ============================================================
# Audit #5 — Windows-typical encodings must still be EVALUATED
# (UTF-8-BOM and UTF-16 are what PowerShell pipelines emit; pre-fix
# these crashed or silently allowed a RED command on the stated
# target platform.)
# ============================================================

_DENY_PAYLOAD = '{"tool_input":{"command":"rm -rf /"}}'


def test_bash_guard_cli_utf8_bom_still_denies():
    proc = _run_guard("bash_guard", b"\xef\xbb\xbf" + _DENY_PAYLOAD.encode("utf-8"))
    _assert_contract(proc, "deny")


def test_bash_guard_cli_utf16le_still_denies():
    proc = _run_guard("bash_guard", _DENY_PAYLOAD.encode("utf-16"))  # includes BOM
    _assert_contract(proc, "deny")


def test_write_guard_cli_utf8_bom_still_denies():
    payload = '{"tool_input":{"file_path":"/h/.claude/settings.json"}}'
    proc = _run_guard("write_guard", b"\xef\xbb\xbf" + payload.encode("utf-8"))
    _assert_contract(proc, "deny")


# ============================================================
# Library-level totality of the extractors (unit form of #2)
# ============================================================


def test_extractors_are_total():
    from agent_shield import bash_guard, write_guard

    for raw in ("", "null", "[1]", '"s"', "42", '{"tool_input": null}',
                '{"tool_input": {"command": 9}}', "{bad json"):
        assert bash_guard._extract_command_from_hook_input(raw) == ""
    for raw in ("", "null", "[1]", '{"tool_input": {"file_path": []}}'):
        assert write_guard._extract_path_from_hook_input(raw) == ""
