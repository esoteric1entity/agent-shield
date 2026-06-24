"""Tests for the ``agent-shield-plugin`` CLI (Phase P3 uninstall-safety)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agent_shield import plugin_cli


@pytest.fixture
def tmp_settings(tmp_path, monkeypatch):
    """Return a user-level settings path under tmp_path and redirect HOME there."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home / ".claude" / "settings.json"


@pytest.fixture
def project_dir(tmp_path):
    """Return a project directory (no .claude yet)."""
    return tmp_path / "project"


def _settings_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def test_enable_creates_hooks_in_user_settings(tmp_settings):
    assert plugin_cli.main(["enable"]) == 0
    data = _settings_json(tmp_settings)
    entries = data["hooks"]["PreToolUse"]
    assert len(entries) == 2
    assert any(e["matcher"] == "Bash" for e in entries)
    assert any(e["matcher"] == "Write|Edit|MultiEdit" for e in entries)
    for entry in entries:
        assert entry["hooks"][0]["type"] == "command"
        assert entry["hooks"][0]["timeout"] == 5


def test_enable_is_idempotent(tmp_settings):
    assert plugin_cli.main(["enable"]) == 0
    assert plugin_cli.main(["enable"]) == 0
    data = _settings_json(tmp_settings)
    assert len(data["hooks"]["PreToolUse"]) == 2


def test_enable_preserves_unrelated_hooks(tmp_settings):
    existing = {"hooks": {"PreToolUse": [{"toolNamePattern": "Bash", "command": "echo other"}]}}
    tmp_settings.parent.mkdir(parents=True, exist_ok=True)
    tmp_settings.write_text(json.dumps(existing), encoding="utf-8")

    assert plugin_cli.main(["enable"]) == 0
    data = _settings_json(tmp_settings)
    entries = data["hooks"]["PreToolUse"]
    assert len(entries) == 3
    assert any(e["command"] == "echo other" for e in entries)


def test_disable_removes_hooks_and_cleans_empty_containers(tmp_settings):
    plugin_cli.main(["enable"])
    assert plugin_cli.main(["disable", "--force"]) == 0
    data = _settings_json(tmp_settings)
    assert "hooks" not in data


def test_disable_is_idempotent(tmp_settings):
    plugin_cli.main(["enable"])
    plugin_cli.main(["disable", "--force"])
    assert plugin_cli.main(["disable", "--force"]) == 0


def test_disable_removes_only_agent_entries(tmp_settings):
    existing = {
        "hooks": {
            "PreToolUse": [
                plugin_cli._BASH_ENTRY,
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo other"}]},
                plugin_cli._WRITE_ENTRY,
            ]
        }
    }
    tmp_settings.parent.mkdir(parents=True, exist_ok=True)
    tmp_settings.write_text(json.dumps(existing), encoding="utf-8")

    assert plugin_cli.main(["disable", "--force"]) == 0
    data = _settings_json(tmp_settings)
    entries = data["hooks"]["PreToolUse"]
    assert len(entries) == 1
    assert entries[0]["hooks"][0]["command"] == "echo other"


def test_disable_removes_legacy_entries(tmp_settings):
    """Early v0.2 alphas wrote the wrong shape; disable must clean them up."""
    existing = {
        "hooks": {
            "PreToolUse": [
                plugin_cli._LEGACY_BASH_ENTRY,
                plugin_cli._LEGACY_WRITE_ENTRY,
            ]
        }
    }
    tmp_settings.parent.mkdir(parents=True, exist_ok=True)
    tmp_settings.write_text(json.dumps(existing), encoding="utf-8")

    assert plugin_cli.main(["disable", "--force"]) == 0
    data = _settings_json(tmp_settings)
    assert "hooks" not in data


def test_status_enabled(tmp_settings):
    plugin_cli.main(["enable"])
    assert plugin_cli.main(["status"]) == 0


def test_status_disabled(tmp_settings):
    assert plugin_cli.main(["status"]) == 1


def test_status_partial(tmp_settings):
    data = {"hooks": {"PreToolUse": [plugin_cli._BASH_ENTRY]}}
    tmp_settings.parent.mkdir(parents=True, exist_ok=True)
    tmp_settings.write_text(json.dumps(data), encoding="utf-8")

    assert plugin_cli.main(["status"]) == 0


def test_enable_creates_dotclaude_dir(tmp_settings):
    # Ensure the parent directory does not exist so enable must create it.
    if tmp_settings.parent.exists():
        shutil.rmtree(tmp_settings.parent)
    assert plugin_cli.main(["enable"]) == 0
    assert tmp_settings.exists()


def test_disable_refuses_non_tty_without_force(tmp_settings, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    plugin_cli.main(["enable"])
    assert plugin_cli.main(["disable"]) == 2


def test_disable_allows_force_in_non_tty(tmp_settings, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    plugin_cli.main(["enable"])
    assert plugin_cli.main(["disable", "--force"]) == 0


def test_disable_prompts_tty_and_accepts_yes(tmp_settings, monkeypatch):
    plugin_cli.main(["enable"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    assert plugin_cli.main(["disable"]) == 0


def test_disable_prompts_tty_and_rejects_no(tmp_settings, monkeypatch):
    plugin_cli.main(["enable"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    assert plugin_cli.main(["disable"]) == 1


def test_malformed_json_is_reported(tmp_settings):
    tmp_settings.parent.mkdir(parents=True, exist_ok=True)
    tmp_settings.write_text("not json", encoding="utf-8")
    assert plugin_cli.main(["status"]) == 2
    assert plugin_cli.main(["enable"]) == 2
    assert plugin_cli.main(["disable", "--force"]) == 2


def test_non_dict_top_level_is_reported(tmp_settings):
    tmp_settings.parent.mkdir(parents=True, exist_ok=True)
    tmp_settings.write_text("[]", encoding="utf-8")
    assert plugin_cli.main(["enable"]) == 2


def test_project_flag_targets_project_settings(project_dir):
    assert plugin_cli.main(["--project", str(project_dir), "enable"]) == 0
    path = project_dir / ".claude" / "settings.json"
    data = _settings_json(path)
    assert len(data["hooks"]["PreToolUse"]) == 2


def test_project_disable_requires_force(project_dir):
    plugin_cli.main(["--project", str(project_dir), "enable"])
    # Non-TTY default in CI; disable without force should be refused.
    assert plugin_cli.main(["--project", str(project_dir), "disable"]) == 2


def test_disable_with_intersersed_options_still_removes(project_dir):
    """argparse accepts global options before the subcommand; ensure disable still works."""
    plugin_cli.main(["--project", str(project_dir), "enable"])
    assert plugin_cli.main(["--project", str(project_dir), "disable", "--force"]) == 0
    data = _settings_json(project_dir / ".claude" / "settings.json")
    assert "hooks" not in data


def test_unsupported_harness_fails(tmp_settings):
    assert plugin_cli.main(["--harness", "openclaw", "status"]) == 2


def test_backup_created_on_mutation(tmp_settings):
    # First enable creates the file, so no backup yet.
    plugin_cli.main(["enable"])
    backups = list(tmp_settings.parent.glob("settings.json.bak.*"))
    assert len(backups) == 0

    # Second mutation (disable) backs up the existing file.
    plugin_cli.main(["disable", "--force"])
    backups = list(tmp_settings.parent.glob("settings.json.bak.*"))
    assert len(backups) == 1


def test_backup_retention_is_capped(tmp_settings, monkeypatch):
    # Speed up the test by patching the cap to a small number.
    monkeypatch.setattr(plugin_cli, "_MAX_BACKUPS", 3)
    plugin_cli.main(["enable"])
    for _ in range(5):
        plugin_cli.main(["disable", "--force"])
        plugin_cli.main(["enable"])
    backups = sorted(tmp_settings.parent.glob("settings.json.bak.*"), key=lambda p: p.stat().st_mtime)
    assert len(backups) == 3
    # Oldest backups were removed.
    assert all(".bak." in b.name for b in backups)


def test_atomic_write_does_not_truncate_on_failure(tmp_settings, monkeypatch):
    plugin_cli.main(["enable"])
    original = tmp_settings.read_text(encoding="utf-8")

    def _raise(*_args, **_kwargs):
        raise OSError("forced")

    monkeypatch.setattr(plugin_cli, "_atomic_write_with_backup", _raise)
    assert plugin_cli.main(["disable", "--force"]) != 0
    assert tmp_settings.read_text(encoding="utf-8") == original


def test_permission_denied_is_clean_error(tmp_settings, monkeypatch):
    plugin_cli.main(["enable"])
    original = tmp_settings.read_text(encoding="utf-8")

    def _raise(*_args, **_kwargs):
        raise PermissionError("denied")

    # Patch the atomic replace step; a failure there must not truncate the file.
    monkeypatch.setattr(os, "replace", _raise)
    assert plugin_cli.main(["disable", "--force"]) == 2
    assert tmp_settings.read_text(encoding="utf-8") == original


def test_status_on_missing_file_returns_disabled(tmp_settings):
    assert plugin_cli.main(["status"]) == 1


def test_enable_idempotent_after_partial_state(tmp_settings):
    data = {"hooks": {"PreToolUse": [plugin_cli._BASH_ENTRY]}}
    tmp_settings.parent.mkdir(parents=True, exist_ok=True)
    tmp_settings.write_text(json.dumps(data), encoding="utf-8")

    assert plugin_cli.main(["enable"]) == 0
    data = _settings_json(tmp_settings)
    assert len(data["hooks"]["PreToolUse"]) == 2


def test_enable_idempotent_after_legacy_partial_state(tmp_settings):
    """enable should not duplicate entries if legacy shapes are present."""
    data = {"hooks": {"PreToolUse": [plugin_cli._LEGACY_BASH_ENTRY, plugin_cli._LEGACY_WRITE_ENTRY]}}
    tmp_settings.parent.mkdir(parents=True, exist_ok=True)
    tmp_settings.write_text(json.dumps(data), encoding="utf-8")

    assert plugin_cli.main(["enable"]) == 0
    data = _settings_json(tmp_settings)
    entries = data["hooks"]["PreToolUse"]
    assert len(entries) == 4
    assert sum(1 for e in entries if e.get("matcher") == "Bash") == 1


def test_subprocess_cli_invocation_smoke(tmp_settings):
    """Exercise the console script entry point via subprocess in non-TTY mode."""
    home = tmp_settings.parent.parent
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)

    proc = subprocess.run(
        [sys.executable, "-m", "agent_shield.plugin_cli", "enable"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert tmp_settings.exists()


@pytest.mark.parametrize("stdin_is_tty,stdout_is_tty,expected", [
    (True, True, None),   # prompts, outcome depends on input
    (True, False, 2),     # stdout not TTY
    (False, True, 2),     # stdin not TTY
    (False, False, 2),    # neither TTY
])
def test_disable_tty_requirement_combinations(tmp_settings, monkeypatch, stdin_is_tty, stdout_is_tty, expected):
    plugin_cli.main(["enable"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: stdin_is_tty)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: stdout_is_tty)
    if expected is None:
        monkeypatch.setattr("builtins.input", lambda _prompt: "no")
        expected = 1
    assert plugin_cli.main(["disable"]) == expected


def test_windows_home_expansion(tmp_path, monkeypatch):
    """When HOME is unset, USERPROFILE should drive the settings path."""
    home = tmp_path / "winhome"
    home.mkdir()
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setenv("USERPROFILE", str(home))
    assert plugin_cli.main(["enable"]) == 0
    assert (home / ".claude" / "settings.json").exists()
