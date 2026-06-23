"""
test_self_lockout_allowlist.py — agent-shield v0.2 Phase F2

The self-lockout allowlist is the ONLY path that skips the catastrophic-RED
check inside ``resolve_error_policy``. It must be NARROW: only commands that
let the operator repair/reinstall agent-shield itself or manage its own
config should be allowed through on the error path.

Allowed classes:
  - pip/uv install/uninstall/upgrade of the literal ``agent-shield`` package
    (or ``pip install -e <path-containing-agent-shield>``)
  - ``agent-shield plugin enable|disable``
  - location probes: ``which agent-shield``, ``command -v agent-shield``,
    ``where agent-shield``
  - Write/Edit paths under ``~/.agent-shield/``, ``/opt/agent-shield/``,
    ``/usr/local/agent-shield/``

Everything else must return False (safe direction), including malformed/empty
input and any callable exception.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import os

import pytest

from agent_shield import _self_lockout_allowlist as allowlist


# ---------------------------------------------------------------------------
# Allowed commands
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "pip install agent-shield",
    "pip3 install agent-shield",
    "pipx install agent-shield",
    "uv install agent-shield",
    "pip install -e ./agent-shield",
    "pip install -e /home/user/agent-shield",
    "pip3 install -e ./agent-shield",
    "pip uninstall agent-shield",
    "pip3 uninstall agent-shield",
    "pipx uninstall agent-shield",
    "uv uninstall agent-shield",
    "pip install --upgrade agent-shield",
    "pip upgrade agent-shield",
    "agent-shield plugin enable",
    "agent-shield plugin disable",
    "which agent-shield",
    "command -v agent-shield",
    "where agent-shield",
])
def test_allowed_commands(cmd):
    assert allowlist.check(cmd) is True


# ---------------------------------------------------------------------------
# Allowed paths (config / repair surface)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", [
    "~/.agent-shield/config.toml",
    os.path.expanduser("~/.agent-shield/config.toml"),
    "~/.agent-shield/observe-counter.json",
    os.path.expanduser("~/.agent-shield/observe-counter.json"),
    "/opt/agent-shield/config.toml",
    "/usr/local/agent-shield/config.toml",
    "/opt/agent-shield/sentinel",
    # Write/Edit tools often include content/new_str keys; the path must still match.
    "~/.agent-shield/config.toml\ncontent=foo",
    os.path.expanduser("~/.agent-shield/config.toml") + "\ncontent=foo",
])
def test_allowed_paths(path):
    assert allowlist.check(path) is True


def test_exact_directory_path_is_allowed():
    assert allowlist.check(os.path.expanduser("~/.agent-shield")) is True
    assert allowlist.check("/opt/agent-shield") is True
    assert allowlist.check("/usr/local/agent-shield") is True


# ---------------------------------------------------------------------------
# Denied: attacker attempts to abuse the allowlist
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    # Not the literal agent-shield package
    "pip install evil-pkg agent-shield",
    "pip install agent-shield-extra",
    "pip install evil-agent-shield",
    "pip install --upgrade agent-shield-lib",
    # Unrelated package management
    "pip install requests",
    "pip uninstall numpy",
    "pip install -e ./some-other-project",
    # No agent-shield subcommand
    "agent-shield status",
    "agent-shield --version",
    # Other commands that happen to contain the words
    "echo agent-shield plugin enable",
    "cat agent-shield plugin disable",
    # Malicious editable-path games (final segment must be exactly agent-shield)
    "pip install -e /tmp/agent-shield-evil",
    "pip install -e /tmp/agent-shield-backdoor",
    "pip install -e /tmp/agent-shield/../../etc/passwd",
    "pip install -e ./agent-shield-evil",
    # Malicious shell games
    "bash -c 'agent-shield plugin enable; rm -rf /'",
    "pip install agent-shield; rm -rf /",
    # Missing command entirely
    "pip install",
    "pip uninstall",
    "",
])
def test_denied_commands(cmd):
    assert allowlist.check(cmd) is False


# ---------------------------------------------------------------------------
# Path normalization bypasses must NOT open the allowlist
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", [
    "~/.agent-shield/../.ssh/id_rsa",          # escape via ..
    "~/.agent-shield//../.ssh/id_rsa",          # double slash + escape
    "/opt/agent-shield/../../etc/passwd",        # escape from /opt
    "~/.agent-shield-evil/config.toml",          # prefix substring, not the dir
    "/opt/agent-shield-evil/config.toml",
    "/opt/agent-shield-extras/config.toml",
    "/usr/local/agent-shield2/config.toml",
    # Substring occurrences of the protected directory must NOT be allowed.
    "/tmp/opt/agent-shield/config.toml",
    "/tmp/home/user/.agent-shield/config.toml",
    "./.agent-shield/config.toml",               # relative paths are NOT absolute, so they are denied
])
def test_path_normalization_does_not_bypass(path):
    assert allowlist.check(path) is False


# ---------------------------------------------------------------------------
# Totality: exceptions in the checker must return False, never raise
# ---------------------------------------------------------------------------
def test_non_string_input_is_denied_safely():
    assert allowlist.check(None) is False
    assert allowlist.check(123) is False
    assert allowlist.check({}) is False
