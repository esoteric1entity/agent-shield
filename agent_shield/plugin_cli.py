"""agent-shield plugin CLI — Phase P3 uninstall-safety.

Provides a small, self-contained CLI for enabling/disabling the Claude Code
PreToolUse hook wiring without manually editing ``~/.claude/settings.json``.

Subcommands:
  enable   - install the two agent-shield PreToolUse entries.
  disable  - remove the two agent-shield PreToolUse entries (requires TTY
             confirmation unless ``--force`` is passed).
  status   - report whether the entries are present.

Design constraints:
  - Never raise out of the CLI; always return an exit code.
  - Atomic write (temp file + rename) plus a timestamped backup.
  - Preserve unrelated hooks and unrelated JSON keys exactly.
  - ``disable`` requires an interactive TTY or explicit ``--force``.
  - Only ``claude_code`` harness is supported in Phase P3; other harnesses
    fail with a clear message.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any


SUPPORTED_HARNESSES = ("claude_code",)

_DEFAULT_HARNESS = "claude_code"

#: Maximum number of timestamped backups to retain per settings file.
_MAX_BACKUPS = 10

#: The PreToolUse entries agent-shield installs. These must match the
#: canonical Claude Code ``matcher`` + ``hooks`` shape documented in
#: examples/claude-code-settings.example.json, README.md, and INSTALL_AGENT.md.
_BASH_ENTRY: dict[str, Any] = {
    "matcher": "Bash",
    "hooks": [
        {
            "type": "command",
            "command": "python -m agent_shield.bash_guard",
            "timeout": 5,
        }
    ],
}
_WRITE_ENTRY: dict[str, Any] = {
    "matcher": "Write|Edit|MultiEdit",
    "hooks": [
        {
            "type": "command",
            "command": "python -m agent_shield.write_guard",
            "timeout": 5,
        }
    ],
}

#: Legacy Phase P3 shapes that the CLI may have written during earlier
#: pre-Phase-P3 alphas. ``disable`` removes these too so users do not end up
#: with stale, non-functional entries after the format correction.
_LEGACY_BASH_ENTRY: dict[str, Any] = {
    "hookEventName": "PreToolUse",
    "toolNamePattern": "Bash",
    "command": "python -m agent_shield.adapters.claude_code",
}
_LEGACY_WRITE_ENTRY: dict[str, Any] = {
    "hookEventName": "PreToolUse",
    "toolNamePattern": "Write|Edit|MultiEdit",
    "command": "python -m agent_shield.adapters.claude_code",
}


def _fail(message: str, code: int = 1) -> int:
    print(f"agent-shield-plugin: {message}", file=sys.stderr)
    return code


def _settings_path(project: Path | None = None) -> Path:
    """Return the Claude Code settings.json path to operate on."""
    if project is not None:
        return project / ".claude" / "settings.json"
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or Path.home()
    return Path(home) / ".claude" / "settings.json"


def _load_settings(path: Path) -> tuple[dict[str, Any] | None, int]:
    """Load settings.json or return (None, exit-code) on hard failure.

    Missing file is treated as an empty dict (success). Malformed JSON or
    non-dict top-level yields an error message and exit code 2.
    """
    if not path.exists():
        return ({}, 0)
    try:
        text = path.read_text(encoding="utf-8-sig")
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return (None, _fail(f"malformed JSON in {path}: {exc}", 2))
    except OSError as exc:
        return (None, _fail(f"cannot read {path}: {exc}", 2))
    if not isinstance(data, dict):
        return (None, _fail(f"top-level value in {path} must be a JSON object", 2))
    return (data, 0)


def _atomic_write_with_backup(path: Path, data: dict[str, Any]) -> int:
    """Write ``data`` to ``path`` atomically, creating a unique timestamped backup first.

    Returns 0 on success, non-zero on failure.

    Keeps at most ``_MAX_BACKUPS`` (10) timestamped backups, removing the oldest
    ones when the cap is exceeded. The backup inherits the original file's
    permission bits so a restrictive ``settings.json`` does not leak to a
    world-readable backup.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        original_mode: int | None = None
        if path.exists():
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
            backup = path.with_suffix(f".json.bak.{ts}")
            counter = 0
            while backup.exists():
                counter += 1
                backup = path.with_suffix(f".json.bak.{ts}.{counter}")
            original_mode = path.stat().st_mode
            # Preserve permissions on the backup copy.
            shutil.copy2(path, backup)

            # Retention: keep only the most recent _MAX_BACKUPS backups.
            existing_backups = sorted(
                path.parent.glob(f"{path.stem}.json.bak.*"),
                key=lambda p: p.stat().st_mtime,
            )
            for old in existing_backups[:-_MAX_BACKUPS]:
                try:
                    old.unlink()
                except OSError:
                    pass

        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, path)
            if original_mode is not None:
                try:
                    os.chmod(path, original_mode)
                except OSError:
                    pass
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return 0
    except OSError as exc:
        return _fail(f"cannot write {path}: {exc}", 2)


def _entry_present(entries: list[Any], needle: dict[str, Any]) -> bool:
    """Return True if ``needle`` is already in ``entries`` (shape comparison)."""
    for entry in entries:
        if isinstance(entry, dict) and entry == needle:
            return True
    return False


def _agent_entries(entries: list[Any]) -> list[int]:
    """Return indices of entries that match the agent-shield shapes.

    Recognises both the canonical ``matcher`` + ``hooks`` shape and the
    legacy ``hookEventName`` + ``command`` shape written by earlier alphas,
    so ``disable`` cleans up stale entries correctly.
    """
    targets = (_BASH_ENTRY, _WRITE_ENTRY, _LEGACY_BASH_ENTRY, _LEGACY_WRITE_ENTRY)
    indices: list[int] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        if entry in targets:
            indices.append(i)
            continue
        # Fuzzy legacy match: any hookEventName entry that points at the old,
        # non-functional module target (regardless of extra keys or a custom
        # toolNamePattern) is also stale wiring we should remove.
        if (
            entry.get("hookEventName")
            and entry.get("command") == "python -m agent_shield.adapters.claude_code"
        ):
            indices.append(i)
    return indices


def _ensure_hooks(settings: dict[str, Any]) -> bool:
    """Create ``hooks.PreToolUse`` if absent and append missing entries.

    Returns True if any change was made.
    """
    changed = False
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        return False
    entries = hooks.setdefault("PreToolUse", [])
    if not isinstance(entries, list):
        return False
    if not _entry_present(entries, _BASH_ENTRY):
        entries.append(_BASH_ENTRY)
        changed = True
    if not _entry_present(entries, _WRITE_ENTRY):
        entries.append(_WRITE_ENTRY)
        changed = True
    return changed


def _remove_hooks(settings: dict[str, Any]) -> bool:
    """Remove the agent-shield PreToolUse entries.

    Returns True if any change was made.
    """
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    entries = hooks.get("PreToolUse")
    if not isinstance(entries, list):
        return False
    indices = _agent_entries(entries)
    if not indices:
        return False
    for i in reversed(indices):
        entries.pop(i)
    if not entries:
        hooks.pop("PreToolUse", None)
    if not hooks:
        settings.pop("hooks", None)
    return True


def _status(settings: dict[str, Any]) -> str:
    """Return ``enabled``, ``partial``, or ``disabled``."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return "disabled"
    entries = hooks.get("PreToolUse")
    if not isinstance(entries, list):
        return "disabled"
    indices = _agent_entries(entries)
    if len(indices) == 0:
        return "disabled"
    if len(indices) == 2:
        return "enabled"
    return "partial"


def _confirm_tty(prompt: str) -> bool:
    """Prompt the user on a TTY and return True for an affirmative answer."""
    try:
        response = input(f"{prompt} [y/N]: ")
    except EOFError:
        return False
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return False
    return response.strip().lower() in ("y", "yes")


def _require_confirmation_or_force(force: bool, action: str) -> int | None:
    """Return None if allowed to proceed, otherwise an exit code.

    Non-TTY ``disable`` without ``--force`` is refused. TTY ``disable`` prompts.
    ``force=True`` bypasses both checks.
    """
    if force:
        return None
    stdin_is_tty = hasattr(sys.stdin, "isatty") and sys.stdin.isatty()
    stdout_is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    if not (stdin_is_tty and stdout_is_tty):
        return _fail(
            f"{action} requires an interactive terminal or explicit --force; "
            "use --force only if you are certain.",
            2,
        )
    if not _confirm_tty(f"Confirm {action}"):
        return _fail(f"{action} cancelled", 1)
    return None


def _cmd_enable(project: Path | None = None) -> int:
    path = _settings_path(project)
    settings, code = _load_settings(path)
    if settings is None:
        return code
    if not _ensure_hooks(settings):
        print(f"agent-shield-plugin: hooks already enabled in {path}")
        return 0
    code = _atomic_write_with_backup(path, settings)
    if code != 0:
        return code
    print(f"agent-shield-plugin: enabled hooks in {path}")
    return 0


def _cmd_disable(project: Path | None = None, force: bool = False) -> int:
    block = _require_confirmation_or_force(force, "disable")
    if block is not None:
        return block
    path = _settings_path(project)
    settings, code = _load_settings(path)
    if settings is None:
        return code
    if not _remove_hooks(settings):
        print(f"agent-shield-plugin: hooks already disabled in {path}")
        return 0
    code = _atomic_write_with_backup(path, settings)
    if code != 0:
        return code
    print(f"agent-shield-plugin: disabled hooks in {path}")
    return 0


def _cmd_status(project: Path | None = None) -> int:
    path = _settings_path(project)
    settings, code = _load_settings(path)
    if settings is None:
        return code
    state = _status(settings)
    print(f"agent-shield-plugin: {state} ({path})")
    return 0 if state != "disabled" else 1


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``agent-shield-plugin`` console script."""
    parser = argparse.ArgumentParser(
        prog="agent-shield-plugin",
        description="Enable, disable, or check the agent-shield runtime hook wiring.",
    )
    parser.add_argument(
        "--harness",
        choices=SUPPORTED_HARNESSES,
        default=_DEFAULT_HARNESS,
        help="Target harness (only claude_code is supported in this phase).",
    )
    parser.add_argument(
        "--project",
        type=Path,
        default=None,
        metavar="DIR",
        help="Operate on DIR/.claude/settings.json instead of the user-level file.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("enable", help="install the agent-shield PreToolUse hooks")
    disable_parser = subparsers.add_parser("disable", help="remove the agent-shield PreToolUse hooks")
    disable_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip the interactive confirmation (use with care).",
    )
    subparsers.add_parser("status", help="report whether the agent-shield hooks are present")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse already printed its error message; convert the exit code to
        # a return value so callers of main() get a clean integer.
        return exc.code if isinstance(exc.code, int) else 2

    if args.harness != _DEFAULT_HARNESS:
        return _fail(
            f"harness '{args.harness}' is not supported by Phase P3; "
            "only --harness claude_code is implemented.",
            2,
        )

    try:
        if args.command == "enable":
            return _cmd_enable(project=args.project)
        if args.command == "disable":
            return _cmd_disable(project=args.project, force=args.force)
        if args.command == "status":
            return _cmd_status(project=args.project)
    except Exception as exc:  # noqa: BLE001 — CLI must never crash
        return _fail(f"unexpected error: {exc}", 2)

    return _fail(f"unknown command: {args.command}", 2)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
