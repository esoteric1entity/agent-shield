"""test_migration_doc_claims.py — pin docs/MIGRATION.md to code facts

The migration guide documents exact legacy and canonical wiring shapes. If those
shapes change in the code, the guide must be updated too; this suite detects drift.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agent_shield import plugin_cli

_ROOT = Path(__file__).resolve().parent.parent


def _migration_text() -> str:
    return (_ROOT / "docs" / "MIGRATION.md").read_text(encoding="utf-8")


_CANONICAL_EXAMPLE = json.loads((_ROOT / "examples" / "claude-code-settings.example.json").read_text(encoding="utf-8"))


def _extract_json_blocks_after(text: str, heading: str) -> list[str]:
    """Return all fenced JSON blocks under *heading*, stopping at the next section."""
    start = text.index(heading)
    region = text[start:]
    # Determine the heading level so we stop at the next peer or higher heading.
    level = len(heading) - len(heading.lstrip("#"))
    section_end_match = re.search(r"\n#" + r"#" * (level - 1) + r" ", region)
    section = region[:section_end_match.start()] if section_end_match else region
    blocks: list[str] = []
    for match in re.finditer(r"```json\s*\n", section):
        fence_start = match.start()
        fence_end = section.index("```", fence_start + len(match.group(0)))
        block = section[fence_start + len(match.group(0)) : fence_end].strip()
        if block:
            blocks.append(block)
    return blocks


def test_migration_mentions_legacy_alpha_security_warning():
    migration = _migration_text()
    lowered = migration.lower()
    assert "security warning" in lowered
    assert "legacy alpha" in lowered
    assert "not actually protected" in lowered


def test_claude_legacy_shapes_match_plugin_cli_legacy_entries():
    """The legacy JSON shown in MIGRATION.md must match the cleanup targets in plugin_cli."""
    migration = _migration_text()
    legacy_blocks = _extract_json_blocks_after(migration, "### Legacy shape")
    legacy_entries = [json.loads(b) for b in legacy_blocks]
    assert plugin_cli._LEGACY_BASH_ENTRY in legacy_entries, (
        "MIGRATION.md does not show the Bash legacy Claude Code shape matching plugin_cli._LEGACY_BASH_ENTRY"
    )
    assert plugin_cli._LEGACY_WRITE_ENTRY in legacy_entries, (
        "MIGRATION.md does not show the Write legacy Claude Code shape matching plugin_cli._LEGACY_WRITE_ENTRY"
    )


def test_claude_canonical_shapes_match_example_json_and_plugin_cli():
    """The canonical JSON shown in MIGRATION.md must match the example file and the CLI constants."""
    migration = _migration_text()
    canonical_blocks = _extract_json_blocks_after(migration, "### Canonical shape")
    canonical_entries = [json.loads(b) for b in canonical_blocks]

    # Strip the inline __comment key from the example entries (not part of the contract).
    example_entries = [
        {k: v for k, v in e.items() if k != "__comment"}
        for e in _CANONICAL_EXAMPLE["hooks"]["PreToolUse"]
    ]
    for entry in example_entries:
        assert entry in canonical_entries, (
            f"MIGRATION.md canonical section does not show {entry['matcher']!r} entry from examples/claude-code-settings.example.json"
        )

    # Three-way parity: plugin_cli constants == example file == MIGRATION.md.
    assert plugin_cli._BASH_ENTRY in canonical_entries, (
        "MIGRATION.md canonical section does not match plugin_cli._BASH_ENTRY"
    )
    assert plugin_cli._WRITE_ENTRY in canonical_entries, (
        "MIGRATION.md canonical section does not match plugin_cli._WRITE_ENTRY"
    )


def test_openclaw_canonical_section_uses_plugin_sdk_shape():
    """The OpenClaw canonical section must reference definePluginEntry + register(api)."""
    migration = _migration_text()
    start = migration.index("## OpenClaw")
    section = migration[start:]
    assert "definePluginEntry" in section
    assert "register(api)" in section
    assert 'api.on("before_tool_call"' in section


def test_openclaw_legacy_section_shows_bare_hooks_export():
    """The OpenClaw legacy section must show the bare export that current loaders skip."""
    migration = _migration_text()
    legacy_start = migration.index("### Legacy shape", migration.index("## OpenClaw"))
    canonical_start = migration.index("### Canonical shape", migration.index("## OpenClaw"))
    legacy_section = migration[legacy_start:canonical_start]
    assert "export const hooks" in legacy_section
    assert "before_tool_call" in legacy_section


def test_openclaw_canonical_section_does_not_contain_legacy_export():
    """The OpenClaw canonical section must not still show the legacy bare-export shape."""
    migration = _migration_text()
    canonical_start = migration.index("### Canonical shape", migration.index("## OpenClaw"))
    migration_end = migration.index("### Migration steps", migration.index("## OpenClaw"))
    canonical_section = migration[canonical_start:migration_end]
    assert "export const hooks" not in canonical_section, (
        "OpenClaw canonical section still contains the legacy bare-export shape"
    )


def test_manual_fallback_instructs_removing_hook_event_name():
    """The manual fallback must explicitly tell users to remove hookEventName entries."""
    migration = _migration_text()
    assert "remove every entry that contains" in migration.lower()
    assert '"hookeventname"' in migration.lower()
    assert '"python -m agent_shield.adapters.claude_code"' in migration


def test_migration_cross_references_are_present():
    """MIGRATION.md must point to the example file, INSTALL_AGENT.md, and adapter_status.md."""
    migration = _migration_text()
    assert "examples/claude-code-settings.example.json" in migration
    assert "INSTALL_AGENT.md" in migration
    assert "docs/adapter_status.md" in migration


def test_migration_warns_about_transient_unprotected_window():
    migration = _migration_text()
    lowered = migration.lower()
    assert "transient window" in lowered
    assert "unprotected" in lowered
