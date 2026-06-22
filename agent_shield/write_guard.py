"""write_guard — PreToolUse hook for Write/Edit operations.

Python port of write-guard.sh (Layer 4 of agent-shield 8-layer architecture).
Guards sensitive configuration files from accidental modification.

3-tier model:
  - RED  (deny)  — Agent's own security infrastructure -> hard block
  - YELLOW (ask) — Important configs, agent templates -> prompt user
  - GREEN (allow) — Everything else -> silent pass

Library use:

    from agent_shield import write_guard

    result = write_guard.check_path("~/.claude/settings.json")
    # GuardResult(decision="deny", reason="Cannot modify Claude settings.json (...)")

CLI use (Claude Code PreToolUse hook compatibility):

    echo '{"tool_input":{"file_path":"~/.claude/settings.json"}}' \\
        | python -m agent_shield.write_guard
"""

from __future__ import annotations

import json
import re
import sys
from typing import Final

from agent_shield._result import GuardResult

# Input-size cap: bound the work so an oversized
# path can't stall the hook into a timeout (a late/errored exit = the write
# proceeds UNEVALUATED). Over the cap, short-circuit to a conservative `ask`.
# Matches the sibling-module caps (sanitize/structured_output/skill_vetting/config).
_MAX_INPUT_CHARS: Final[int] = 1_000_000
_MAX_READ_BYTES: Final[int] = _MAX_INPUT_CHARS * 4  # UTF-8 worst case for the char cap

# =============================================================================
# Path normalization
# =============================================================================


def _collapse_segments(norm: str) -> str:
    """Collapse ``//``→``/`` and resolve ``.``/``..`` segments on a slash-form
    path (drive already peeled). So a path that RESOLVES to a guarded file
    cannot dodge a ``$``-anchored RED pattern by spelling (``a//b``, ``a/./b``,
    ``a/c/../b``). Pure-lexical (no filesystem touch), whole-segment only — so
    ``foo..``, ``..bar``, ``settings.json.md`` are never altered. A ``..`` above
    a rooted path is dropped (can't escape root); a leading ``..`` on a relative
    path is preserved. Mirrored in tests/write-guard.sh.
    """
    rooted = norm.startswith("/")
    out: list[str] = []
    for seg in norm.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not rooted:
                out.append("..")
            # a '..' above a rooted path is dropped (can't escape root)
            continue
        # Win32 strips a trailing dot/space from EACH path component, not just the
        # final one — so a guarded directory spelled 'agent_shield.' or '.claude.'
        # resolves to the dot-less dir and would dodge a $-anchored RED pattern.
        # Strip per-segment to close that bypass. re.ASCII keeps
        # parity with the bash mirror's POSIX [[:space:]] class.
        seg = re.sub(r"[\s.]+$", "", seg, flags=re.ASCII)
        if seg:
            out.append(seg)
    joined = "/".join(out)
    return ("/" + joined) if rooted else joined


def _normalize_path(file_path: str) -> str:
    """Normalize a file path for guard matching.

    Collapses the Windows path-equivalence class so a ``$``-anchored RED
    pattern can't be bypassed by a path that resolves to the SAME file:

    - Backslashes → forward slashes; lowercased (case-insensitive matching).
    - **NTFS alternate-data-stream suffix stripped** on the final segment.
      ADS uses a *single* colon (``file.py:stream``) — and the default data
      stream ``file.py::$DATA`` IS the file's real content. A colon is illegal
      in a normal Windows filename, so any colon in the basename means ADS;
      we drop from the first colon in the last path segment, after peeling an
      ``X:`` drive prefix so the drive colon survives.
    - **Trailing ASCII whitespace and dots stripped** — Windows' Win32
      path canonicalization removes trailing spaces and dots (a trailing
      space, or ``file.py.``, opens ``file.py``). This strips the full
      ASCII-whitespace class (space, tab, newline, CR, form-feed,
      vertical-tab) plus dots — an intentional *superset* of Win32's
      space+dot, kept in exact parity with the bash mirror's POSIX
      ``[[:space:]]`` class. Over-stripping only ever over-blocks; it can
      never open a bypass. Non-ASCII whitespace (e.g. NBSP, U+00A0) is
      **NOT** stripped — a NBSP-suffixed path is a genuinely distinct
      file. The ``re.ASCII`` flag holds this parity: without it Python's
      Unicode whitespace matching would strip NBSP while the ASCII-only
      bash mirror would not, and the two hooks would disagree.

    Earlier normalization used a too-narrow ``split('::')`` + ``rstrip(' .')``
    that missed single-colon ADS and tab/other-whitespace; this is the
    generalized fix. Mirrored in tests/write-guard.sh normalization.
    """
    norm = file_path.replace("\\", "/").lower()
    # Peel an optional drive-letter prefix so its colon isn't read as ADS.
    drive = ""
    if len(norm) >= 2 and norm[1] == ":" and norm[0].isalpha():
        drive, norm = norm[:2], norm[2:]
    # Collapse redundant separators + resolve '.'/'..' so a path that resolves
    # to a guarded file can't dodge a $-anchored RED pattern by spelling.
    norm = _collapse_segments(norm)
    # Strip an ADS stream from the final path segment (first colon onward).
    slash = norm.rfind("/")
    head, base = (norm[: slash + 1], norm[slash + 1 :]) if slash >= 0 else ("", norm)
    base = base.split(":", 1)[0]
    norm = drive + head + base
    # Strip trailing ASCII whitespace (space/tab/newline/CR/FF/VT) + dots.
    # re.ASCII keeps \s ASCII-only so this matches the bash mirror's POSIX
    # [[:space:]] class exactly; NBSP & other non-ASCII whitespace are kept.
    return re.sub(r"[\s.]+$", "", norm, flags=re.ASCII)


# =============================================================================
# RED TIER — Hard block. Self-modification of security infrastructure.
# =============================================================================
_RED_PATTERNS: Final[tuple[tuple[re.Pattern[str], str, str], ...]] = (
    # Each entry is (pattern, reason, pattern_id). The ``pattern_id`` is a short
    # descriptive snake_case slug single-sourced HERE (the RED table is the one
    # source of truth — ``is_red()`` and ``--red-only`` read it, no codegen/drift).
    # The regexes and reasons are UNCHANGED; only the id field is added.
    # The hooks themselves (self-modification attack vector).
    # Hardening fix (2026-06-08): also protect the canonical Python
    # package files. The previous pattern only matched the legacy `hooks/scripts/*.sh`
    # deployment, leaving `agent_shield/*.py` (the canonical implementation) UNPROTECTED.
    # An attacker / confused agent could `Edit agent_shield/bash_guard.py` to neuter
    # the RED tier, and write_guard would silently `allow` it. The `(^|/)` prefix
    # covers both vendored (`agent_shield/...`) and site-packages install layouts.
    (
        re.compile(r"(^|/)agent_shield/(bash_guard|write_guard|_result|__init__)\.py$"),
        "Cannot modify active agent-shield guard module (self-modification attack vector)",
        "self_modify_guard_module",
    ),
    # The legacy bash deployment (kept for back-compat with installs using the bash hooks).
    (
        re.compile(r"hooks/scripts/(bash-guard|write-guard)\.sh$"),
        "Cannot modify active security hook scripts",
        "self_modify_hook_script",
    ),
    # Claude's settings.json
    (
        re.compile(r"\.claude/settings\.json$"),
        "Cannot modify Claude settings.json (contains hook/permission configs)",
        "claude_settings_json",
    ),
    # Claude's settings.local.json
    (
        re.compile(r"\.claude/settings\.local\.json$"),
        "Cannot modify Claude settings.local.json (contains hook/permission configs)",
        "claude_settings_local_json",
    ),
    # SSH private keys — UNAMBIGUOUSLY secret (id_rsa / id_ed25519 / …), so a
    # hard block has effectively no false positives. (The generic `.pem`/`.key`
    # extension match is YELLOW, not RED — see the YELLOW tier — because those
    # extensions are content-blind: `fullchain.pem` is a public cert and `.key`
    # is also Apple Keynote's document type.)
    (
        re.compile(r"(^|/)\.ssh/id_[a-z0-9_]+$"),
        "Cannot overwrite SSH private key",
        "ssh_private_key",
    ),
    # OpenClaw environment file (per-provider API keys) — same class as
    # .claude/settings.json: the agent's own credential surface.
    (
        re.compile(r"\.openclaw/\.env$"),
        "Cannot modify .openclaw/.env (agent API credentials)",
        "openclaw_env",
    ),
)

# =============================================================================
# YELLOW TIER — Ask user. Important but sometimes legitimate to modify.
# =============================================================================
_YELLOW_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    # agent-shield policy config (Layer 7). Editing it changes the agent's own
    # security policy — config is NOT a trust boundary, so an attacker/confused
    # agent who can edit it can weaken posture. ASK (not deny): the file is meant
    # to be user-edited. Two default basenames; a config at a non-default
    # $AGENT_SHIELD_CONFIG location cannot be matched by a static pattern (a
    # stated limitation — see docs/CONFIGURATION.md). Anchored on the basename so
    # ~-expansion / absolute / relative spellings all collapse via _normalize_path.
    (
        re.compile(r"(^|/)agent-shield\.toml$", re.IGNORECASE),
        "Modifying agent-shield policy config — confirm intentional (config is not a trust boundary)",
    ),
    (
        re.compile(r"(^|/)\.agent-shield/config\.toml$", re.IGNORECASE),
        "Modifying agent-shield policy config — confirm intentional (config is not a trust boundary)",
    ),
    # Agent templates (Sentinel, Vault, Clerk definitions)
    (
        re.compile(r"agents/.*\.md$", re.IGNORECASE),
        "Modifying agent template — confirm this change is intentional",
    ),
    # Orchestration rules
    (
        re.compile(r"\.claude/rules/.*\.md$", re.IGNORECASE),
        "Modifying orchestration rules — confirm this change is intentional",
    ),
    # Other hook scripts (not the guards themselves)
    (
        re.compile(r"hooks/scripts/.*\.(sh|js|py)$", re.IGNORECASE),
        "Modifying hook script — confirm this change is intentional",
    ),
    # Memory files (Vault's domain)
    (
        re.compile(r"/memory/.*\.md$", re.IGNORECASE),
        "Modifying memory file — should this go through Vault instead?",
    ),
    # Environment files
    (
        re.compile(r"\.(env|env\.local|env\.production)$", re.IGNORECASE),
        "Modifying environment file — may contain secrets",
    ),
    # Shell startup files — classic persistence vector, but legitimate edits
    # are common, so ask rather than deny.
    (
        re.compile(
            r"(^|/)\.(bashrc|bash_profile|bash_login|bash_logout|zshrc|zprofile|profile)$",
            re.IGNORECASE,
        ),
        "Modifying shell startup file — common persistence vector; confirm intentional",
    ),
    # Credential-bearing files
    (
        re.compile(
            r"(credentials|secrets|tokens|passwords)\.(json|yaml|yml|toml|ini|txt)$",
            re.IGNORECASE,
        ),
        "Modifying file that may contain credentials",
    ),
    # Key/cert files by extension — `ask`, not `deny`. A real private key here would be unrecoverable to overwrite,
    # but the extension is content-blind: `fullchain.pem` is a public cert and
    # `.key` is also Apple Keynote's document type, so a hard block would be a
    # surprise false positive. Confirming with the user protects the real keys
    # without blocking the lookalikes. (SSH id_* keys stay RED above.)
    (
        re.compile(r"\.(pem|key)$", re.IGNORECASE),
        "Modifying a .pem/.key file — confirm this isn't a private key you meant to keep",
    ),
    # CLAUDE.md instruction files
    (
        re.compile(r"claude\.md$", re.IGNORECASE),
        "Modifying CLAUDE.md instruction file — affects Claude behavior",
    ),
    # Sync protocol files — `(^|/)` boundary keeps dirnames like `mysync/` from matching
    (
        re.compile(r"(^|/)(claude_)?sync/.*\.md$", re.IGNORECASE),
        "Modifying sync protocol file — affects cross-instance communication",
    ),
)


def check_path(file_path: str) -> GuardResult:
    """Check a file path and return a GuardResult.

    Args:
        file_path: The target file path (as passed to a Write/Edit tool).

    Returns:
        GuardResult with decision in {"deny", "ask", "allow"}.

    Parse-failure behavior:
        If ``file_path`` is empty or None, returns ``allow`` (matches bash
        version's defensive default — never block on parse errors).
    """
    if not file_path:
        return GuardResult(decision="allow")

    if len(file_path) > _MAX_INPUT_CHARS:
        return GuardResult(
            decision="ask",
            reason="Path exceeds the size cap and was not fully evaluated — confirm manually",
        )

    norm_path = _normalize_path(file_path)

    # RED tier — hard block (first match wins)
    for pattern, reason, _pattern_id in _RED_PATTERNS:
        if pattern.search(norm_path):
            return GuardResult(decision="deny", reason=reason)

    # YELLOW tier — ask user (first match wins)
    for pattern, reason in _YELLOW_PATTERNS:
        if pattern.search(norm_path):
            return GuardResult(decision="ask", reason=reason)

    # GREEN tier — allow silently
    return GuardResult(decision="allow")


def is_red(file_path: str) -> tuple[bool, str]:
    """Return whether ``file_path`` hits a RED pattern, with its ``pattern_id``.

    Normalizes the path the SAME way :func:`check_path` does, then reuses
    ``_RED_PATTERNS`` (the single source of truth) with the same
    first-match-wins order — so the reported ``pattern_id`` always identifies
    the entry that ``check_path`` would deny on.

    Returns:
        ``(True, pattern_id)`` on the first RED match, else ``(False, "")``.
        Empty/None or over-cap input is treated as not-RED (``(False, "")``).
    """
    if not file_path or len(file_path) > _MAX_INPUT_CHARS:
        return (False, "")
    norm_path = _normalize_path(file_path)
    for pattern, _reason, pattern_id in _RED_PATTERNS:
        if pattern.search(norm_path):
            return (True, pattern_id)
    return (False, "")


def _run_red_only(file_path: str) -> int:
    """``--red-only`` sub-mode: print ``{"red": bool, "pattern_id": str}``.

    A library/CI probe that exposes the RED verdict alone (no YELLOW/GREEN,
    no hook JSON). Always returns 0 — same never-crash contract as the hook
    path.
    """
    red, pattern_id = is_red(file_path)
    sys.stdout.write(json.dumps({"red": red, "pattern_id": pattern_id}))
    return 0


def _extract_path_from_hook_input(input_text: str) -> str:
    """Extract the file_path from Claude Code PreToolUse hook stdin JSON.

    Expected shape: {"tool_name": "Write"|"Edit", "tool_input": {"file_path": "..."}}.
    Total function: any malformed shape — non-dict top level,
    non-dict tool_input, non-string file_path — returns "" instead of raising.
    Pre-fix, a top-level list/null or a non-string file_path crashed main()
    with exit 1, so the write was never evaluated (silent bypass).
    """
    try:
        data = json.loads(input_text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        return ""
    path = tool_input.get("file_path")
    return path if isinstance(path, str) else ""


def _decode_stdin_bytes(raw: bytes) -> str:
    """Decode hook stdin defensively.

    Windows pipelines (PowerShell in particular) commonly emit UTF-8-BOM or
    UTF-16; a strict utf-8 text read raised UnicodeDecodeError on the stated
    target platform — crash, write never evaluated. BOM-sniff UTF-16,
    default to utf-8-sig, never raise.
    """
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Reads JSON from stdin; outputs hook JSON to stdout.

    Compatible with Claude Code PreToolUse hooks. Always returns exit code 0;
    the decision is communicated via the stdout JSON payload (or empty stdout
    for allow). A non-zero exit is a hook ERROR (not a block) in Claude Code —
    the operation would proceed unevaluated — so the contract is enforced
    with a top-level catch-all. Documented limitation: input that cannot be
    parsed cannot be evaluated and is therefore allowed, matching the bash
    source's parse-failure default.
    """
    try:
        if argv and "--red-only" in argv:
            # --red-only <path>: emit only the RED verdict + pattern_id.
            # The next positional (first non-flag token after --red-only) is the
            # path; a missing positional yields the not-RED verdict (no crash).
            rest = argv[argv.index("--red-only") + 1:]
            path = next((tok for tok in rest if not tok.startswith("-")), "")
            return _run_red_only(path)
        stream = getattr(sys.stdin, "buffer", None)
        if stream is not None:
            raw = stream.read(_MAX_READ_BYTES + 1)
            oversize = len(raw) > _MAX_READ_BYTES
            stdin_text = _decode_stdin_bytes(raw)
        else:
            stdin_text = sys.stdin.read(_MAX_READ_BYTES + 1)
            oversize = len(stdin_text) > _MAX_READ_BYTES
        if oversize:
            # Don't trust a truncated parse — ask conservatively.
            result = GuardResult(decision="ask", reason="Hook input exceeds the size cap — confirm manually")
        else:
            from .adapters import claude_code  # function-local: avoids import cycle
            path = _extract_path_from_hook_input(stdin_text)
            result = claude_code.decide({"tool_name": "Write", "tool_input": {"file_path": path}})
        hook_json = result.to_hook_json()
        if hook_json is not None:
            sys.stdout.write(json.dumps(hook_json))
    except Exception:  # noqa: BLE001 — guard contract: never crash
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
