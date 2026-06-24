"""_self_lockout_allowlist — agent-shield v0.2 Phase F2.

The narrow allowlist used by ``resolve_error_policy`` at step 1. This is the ONLY
path that skips the catastrophic-RED check, so it must be strictly limited to
commands/paths that repair or reinstall agent-shield itself. Anything not on the
list returns ``False``; any unexpected input or internal error also returns
``False`` (the safe direction: no allow-exception).

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import re

import os

from agent_shield import write_guard

#: Repair/reinstall package commands. The PyPI distribution name must be the
#: LITERAL ``ai-agent-shield`` token (with optional extras and/or version
#: specifier). Editable installs are allowed when their FINAL path segment is
#: ``agent-shield`` (the repository directory name). Flags may appear between the
#: verb and the package name.
_ALLOWED_INSTALL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"^\s*(pip|pip3|pipx|uv(?:\s+pip)?)\s+install\s+(?:--?\S+\s+)*-e\s+(?:.*[/\\])?agent-shield/?\s*$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^\s*(pip|pip3|pipx|uv(?:\s+pip)?)\s+install\s+(?:--?\S+\s+)*ai-agent-shield(?:\[[^\]]+\])?(?:==[^\s]+)?(?:\[[^\]]+\])?\s*$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^\s*(pip|pip3|pipx|uv(?:\s+pip)?)\s+(?:uninstall|upgrade)\s+(?:--?\S+\s+)*ai-agent-shield(?:\[[^\]]+\])?(?:==[^\s]+)?(?:\[[^\]]+\])?\s*$",
        re.IGNORECASE,
    ),
)

#: agent-shield subcommand surface used to enable/disable the plugin/hook.
#: Only the base enable/disable verbs are allowed; flag-bearing variants
#: (e.g. ``--force``) are deliberately denied.
_ALLOWED_PLUGIN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*agent-shield-plugin\s+(enable|disable)\s*$", re.IGNORECASE),
    re.compile(
        r"^\s*python(3|\.exe)?\s+-m\s+agent_shield\.plugin_cli\s+(enable|disable)\s*$",
        re.IGNORECASE,
    ),
)

#: Diagnostic location probes for the plugin helper (the only top-level
#: ``agent-shield-*`` console script an operator types interactively).
_ALLOWED_PROBE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*(which|command\s+-v|where)\s+agent-shield-plugin\s*$", re.IGNORECASE),
)

#: Protected installation directories whose contents may be edited to repair
#: the package or its configuration. Paths are normalized the same way the write
#: guard normalizes them (backslashes, lowercased, segments collapsed), and a
#: leading ``~`` is expanded to the user's home directory. Each prefix is stored
#: as a normalized absolute path so the allowlist only matches the intended
#: directory tree, not an arbitrary substring occurrence.
def _norm_prefix(path: str) -> str:
    """Normalize a protected-directory prefix and guarantee a trailing slash."""
    p = write_guard.normalize_path(os.path.expanduser(path))
    if not p.endswith("/"):
        p += "/"
    return p


_ALLOWED_PATH_PREFIXES: tuple[str, ...] = (
    _norm_prefix("~/.agent-shield/"),
    _norm_prefix("/opt/agent-shield/"),
    _norm_prefix("/usr/local/agent-shield/"),
)


def check(raw: str) -> bool:
    """Return True if ``raw`` is a narrow self-repair allowlist entry.

    Handles both command-like strings and path-like strings. Returns False on
    any non-string input or unexpected error (safe direction).
    """
    try:
        if not isinstance(raw, str) or not raw.strip():
            return False
        text = raw.strip()

        # Command-like allowlist
        for pattern in _ALLOWED_INSTALL_PATTERNS:
            if pattern.match(text):
                return True
        for pattern in _ALLOWED_PLUGIN_PATTERNS:
            if pattern.match(text):
                return True
        for pattern in _ALLOWED_PROBE_PATTERNS:
            if pattern.match(text):
                return True

        # Path-like allowlist: normalize the first line (Write/Edit payloads
        # may contain extra keys), expand a leading ``~`` for parity with how
        # operators actually spell config paths, and test against protected
        # absolute prefixes. Using ``startswith`` (and exact-dir equality)
        # prevents arbitrary substring matches such as ``/tmp/opt/agent-shield/``.
        first_line = text.splitlines()[0]
        expanded = os.path.expanduser(first_line)
        norm = write_guard.normalize_path(expanded)
        for prefix in _ALLOWED_PATH_PREFIXES:
            if norm.startswith(prefix) or norm == prefix.rstrip("/"):
                return True

        return False
    except Exception:  # noqa: BLE001 — never let an allowlist bug allow anything
        return False
