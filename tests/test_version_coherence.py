"""test_version_coherence.py — one canonical version string across all shipped files

Version literals appear in multiple user-facing files. This test treats the
`pyproject.toml` `project.version` field as the single source of truth and asserts
that every other shipped occurrence matches it, so a bump cannot silently drift.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "version not found in pyproject.toml"
    return match.group(1)


_CANONICAL = _pyproject_version()


def test_pyproject_version_is_defined():
    assert _CANONICAL
    # Sanity: we expect pre-release alpha versions like 0.1.0a5.
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?", _CANONICAL)


def test_init_fallback_matches_pyproject():
    text = (_ROOT / "agent_shield" / "__init__.py").read_text(encoding="utf-8")
    assert _CANONICAL in text, "agent_shield/__init__.py fallback version does not match pyproject.toml"


def test_citation_cff_version_matches_pyproject():
    text = (_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert f"version: {_CANONICAL}" in text


def test_readme_badge_version_matches_pyproject():
    text = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert f"v{_CANONICAL}_alpha" in text


def test_install_agent_version_matches_pyproject():
    text = (_ROOT / "INSTALL_AGENT.md").read_text(encoding="utf-8")
    assert f"agent-shield {_CANONICAL}" in text
    assert f"`{_CANONICAL}`" in text


def test_bug_report_template_version_matches_pyproject():
    text = (_ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml").read_text(encoding="utf-8")
    occurrences = text.count(_CANONICAL)
    assert occurrences >= 2, (
        f"bug_report.yml should mention {_CANONICAL} at least twice (reproduce steps + placeholder)"
    )


def test_openclaw_plugin_package_json_version_matches_pyproject():
    text = (_ROOT / "agent_shield" / "adapters" / "openclaw_plugin" / "package.json").read_text(encoding="utf-8")
    assert f'"version": "{_CANONICAL}"' in text
