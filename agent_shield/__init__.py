"""agent-shield — defensive overlay for AI agents.

8-layer architecture; v0.1.0 ships 6 layers — skill_vetting (1), sanitize (2),
structured_output (3), bash_guard + write_guard (4, the runtime hooks), audit
(6), config (7). Layers 0 (operational) and 5 (network egress) are pre-release.

See the per-module files for each layer's public API.

Note: bash_guard / write_guard are NOT imported eagerly here — `from
agent_shield import bash_guard` resolves them on demand, and eager imports
would make `python -m agent_shield.bash_guard` emit a RuntimeWarning
("found in sys.modules") on every hook invocation.
"""

from agent_shield._result import GuardResult


def _resolve_version() -> str:
    """Single-source the version from installed package metadata so it can't
    drift from pyproject.toml. Falls back to a literal only when running from a
    source tree that was never installed (e.g. a raw git checkout). The
    importlib.metadata names stay function-local — never bound at module scope.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover - importlib.metadata is stdlib on 3.11
        return "0.1.0a4"
    try:
        return version("agent-shield")
    except PackageNotFoundError:
        return "0.1.0a4"


__version__ = _resolve_version()

__all__ = ["GuardResult", "bash_guard", "write_guard", "skill_vetting",
           "sanitize", "structured_output", "audit", "config"]
