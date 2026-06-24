"""bash_guard — PreToolUse hook for Bash commands.

Python port of bash-guard.sh (Layer 4 of agent-shield 8-layer architecture).
Preserves the 3-tier RED/YELLOW/GREEN model:
  - RED  (deny)  — Catastrophic/destructive patterns -> hard block
  - YELLOW (ask) — Suspicious patterns -> prompt user for confirmation
  - GREEN (allow) — Everything else -> silent pass

The Python port aims for behavioral equivalence with the .sh source.
See ``tests/test_bash_write_guards.py`` for equivalence tests.

Library use:

    from agent_shield import bash_guard

    result = bash_guard.check_command("rm -rf /")
    # GuardResult(decision="deny", reason="Destructive rm -rf targeting root directory")

CLI use (Claude Code PreToolUse hook compatibility):

    echo '{"tool_input":{"command":"rm -rf /"}}' | python -m agent_shield.bash_guard
"""

from __future__ import annotations

import json
import re
import sys
from typing import Final

from agent_shield._result import GuardResult

# py↔bash parity: compile every pattern with
# re.ASCII so \s/\w/\b are ASCII-only and match the bash mirror's POSIX classes
# exactly. Without it, Python's Unicode-aware \s matches NBSP/thin/ideographic
# space while the grep mirror does not — the two ports would disagree on a
# Unicode-whitespace-laced command. (same class of fix as in write_guard.)
_FLAGS: Final[int] = re.IGNORECASE | re.ASCII
_FLAGS_ML: Final[int] = re.IGNORECASE | re.MULTILINE | re.ASCII

# Recursive-force rm flag cluster — matches any bundling/ordering that contains
# BOTH r and f (e.g. -rf, -fr, -rfv, -fvr, -vrf), so adding a verbose/extra flag
# letter or reordering the cluster cannot bypass the rm-root protection. Bounded
# quantifiers ({0,12}) keep it linear (ReDoS-safe) and POSIX-ERE-portable to the
# bash mirror's `grep -E`. The root pattern below additionally tolerates an
# end-of-options `--` and intervening option tokens before the target.
_RM_RF: Final[str] = (
    r"-([a-z]{0,12}r[a-z]{0,12}f[a-z]{0,12}|[a-z]{0,12}f[a-z]{0,12}r[a-z]{0,12})"
)

# Split-flag recursive-force form — r and f live in SEPARATE tokens
# (`rm -r -f`, `-rv -f`, `-r -fv`, with optional intervening flag tokens between
# them). Each token may bundle extra letters (same cluster idea as _RM_RF), so a
# split where one side carries a verbose/extra flag still matches. Bounded
# ({0,12}) for ReDoS safety; POSIX-ERE-portable to the bash mirror.
_RM_SPLIT: Final[str] = (
    r"(-[a-z]{0,12}r[a-z]{0,12}\s+(?:-{1,2}\S+\s+)*-[a-z]{0,12}f[a-z]{0,12}"
    r"|-[a-z]{0,12}f[a-z]{0,12}\s+(?:-{1,2}\S+\s+)*-[a-z]{0,12}r[a-z]{0,12})"
)

# Input-size cap: bound the work so an oversized
# command can't stall the hook into a timeout — a late/errored hook exit means
# the call proceeds UNEVALUATED (a silent bypass). Over the cap we short-circuit
# to a conservative `ask` (never silently `allow`). Matches the 1M/2M caps on the
# sibling modules (sanitize, structured_output, skill_vetting, config).
_MAX_INPUT_CHARS: Final[int] = 1_000_000
_MAX_READ_BYTES: Final[int] = _MAX_INPUT_CHARS * 4  # UTF-8 worst case for the char cap


class _LineStagedSearch:
    """ReDoS-safe replacement for ``A.*B.*C``-shaped regexes.

    Matches when every stage matches IN ORDER within a single line — the same
    semantics as ``A.*B.*C`` (``.`` does not cross newlines) and as the bash
    source's per-line ``grep -E``, but in linear time. The original
    credential-exfil regex had two unbounded ``.*`` gaps; a ~150KB adversarial
    command took ~12s of backtracking, long enough to time out the hook.
    Duck-types ``re.Pattern.search`` so the tier loops treat it uniformly.
    (The bash source needs no equivalent change: GNU grep's ERE engine is
    DFA-based and already linear.)
    """

    def __init__(self, *stages: str, flags: int = _FLAGS) -> None:
        self._stages = tuple(re.compile(s, flags) for s in stages)

    def search(self, text: str) -> re.Match[str] | None:
        for line in text.split("\n"):
            pos = 0
            match: re.Match[str] | None = None
            for stage in self._stages:
                match = stage.search(line, pos)
                if match is None:
                    break
                pos = match.end()
            if match is not None:
                return match
        return None


# Command-position prefix for destructive *verbs* (mkfs, dd, format, del, …).
# The prior `(^|[;&|]\s*)` matched start-of-STRING
# only (no re.MULTILINE), so a destructive verb on a non-first line of a
# compound command bypassed the guard — and the per-line bash `grep` did NOT,
# so the two ports DISAGREED on real multi-line attacks. This prefix:
#   - is used with re.MULTILINE so `^` matches the start of EVERY line
#     (parity with the bash sources' line-oriented grep);
#   - allows leading whitespace and shell env-var assignments
#     (`   dd …`, `FOO=1 dd …`) which previously slipped the anchor;
#   - uses only disjoint character classes (`\S`/`\s`, `\w`), so it is linear.
# A shell-invocation / eval / xargs lead-in is a command introducer too — a
# destructive verb inside `bash -c '…'`, `eval …`, or `xargs …` is at command
# position even though no ^/;/&/| precedes it.
# Mirrored in tests/bash-guard.sh SHELL_INTRO.
_SHELL_INTRO: Final[str] = (
    # Tolerate option tokens before -c (bash --norc -c, bash -i -c,
    # sh -e -c) and xargs option-VALUES (xargs -I {} VERB, xargs -P 4 -n 1 VERB).
    r"(?:(?:bash|sh|zsh|dash|ash)\s+(?:-{1,2}\S+\s+)*-[a-zA-Z]*c\s+['\"]?"
    r"|eval\s+['\"]?"
    r"|xargs\s+(?:-\S+\s+(?:[^-\s]\S*\s+)?)*)"
)
_CMD_START: Final[str] = r"(?:^|[;&|]|" + _SHELL_INTRO + r")\s*(?:\w+=\S*\s+)*"

# =============================================================================
# RED TIER patterns — Hard block. Catastrophic/destructive.
# Order matters: more-specific patterns first.
# =============================================================================
_RED_PATTERNS: Final[
    tuple[tuple[re.Pattern[str] | _LineStagedSearch, str, str], ...]
] = (
    # Each entry is (pattern, reason, pattern_id). The ``pattern_id`` is a short
    # descriptive snake_case slug single-sourced HERE (the RED table is the one
    # source of truth — ``is_red()`` and ``--red-only`` read it, no codegen/drift).
    # The regexes and reasons are UNCHANGED; only the id field is added.
    # Destructive rm targeting root
    (
        # A trailing shell separator/terminator/quote
        # after `/` (`rm -rf /;`, `/&`, `/|cat`, `rm -rf /'`) resolves to root but
        # the old `(\s|$|\*)` tail downgraded it to YELLOW. Mirrored in bash-guard.sh.
        re.compile(r"rm\s+" + _RM_RF + r"\s+(?:-{1,2}\S+\s+)*/([\s;&|<>)'\"]|$|\*)", _FLAGS),
        "Destructive rm -rf targeting root directory",
        "rm_recursive_root",
    ),
    # Cheap literal evasions of the above:
    # quoted root, split flags, home/cwd targets.
    (
        re.compile(r"rm\s+" + _RM_RF + r"""\s+(?:-{1,2}\S+\s+)*["']/["']""", _FLAGS),
        "Destructive rm -rf targeting root directory (quoted)",
        "rm_recursive_root_quoted",
    ),
    (
        re.compile(r"rm\s+" + _RM_SPLIT + r"\s+(?:-{1,2}\S+\s+)*/([\s;&|<>)'\"]|$|\*)", _FLAGS),
        "Destructive rm -rf targeting root directory (split flags)",
        "rm_recursive_root_split",
    ),
    (
        re.compile(r"rm\s+" + _RM_RF + r"\s+(?:-{1,2}\S+\s+)*(~|\$HOME)/?([\s;&|<>)]|$)", _FLAGS),
        "Destructive rm -rf targeting home directory",
        "rm_recursive_home",
    ),
    (
        re.compile(r"rm\s+" + _RM_RF + r"\s+(?:-{1,2}\S+\s+)*\.\.?([\s;&|<>)]|$)", _FLAGS),
        "Destructive rm -rf targeting current/parent directory",
        "rm_recursive_cwd_parent",
    ),
    # Destructive rm targeting Windows system paths
    (
        re.compile(r"rm\s+" + _RM_RF + r"\s+(?:-{1,2}\S+\s+)*/c/(Windows|Program|Users\s*$)", _FLAGS),
        "Destructive rm -rf targeting system-critical Windows path",
        "rm_recursive_windows_system",
    ),
    # Split-flag form (rm -r -f, -rv -f) at the non-root critical targets —
    # mirrors the single-token cluster patterns above so RED coverage is uniform
    # across quoted-root / home / parent / Windows for the split spelling too.
    # (Split-form root is covered by the split-flag root pattern above.)
    (
        re.compile(r"rm\s+" + _RM_SPLIT + r"""\s+(?:-{1,2}\S+\s+)*["']/["']""", _FLAGS),
        "Destructive rm -rf targeting root directory (quoted)",
        "rm_recursive_root_quoted_split",
    ),
    (
        re.compile(r"rm\s+" + _RM_SPLIT + r"\s+(?:-{1,2}\S+\s+)*(~|\$HOME)/?([\s;&|<>)]|$)", _FLAGS),
        "Destructive rm -rf targeting home directory",
        "rm_recursive_home_split",
    ),
    (
        re.compile(r"rm\s+" + _RM_SPLIT + r"\s+(?:-{1,2}\S+\s+)*\.\.?([\s;&|<>)]|$)", _FLAGS),
        "Destructive rm -rf targeting current/parent directory",
        "rm_recursive_cwd_parent_split",
    ),
    (
        re.compile(r"rm\s+" + _RM_SPLIT + r"\s+(?:-{1,2}\S+\s+)*/c/(Windows|Program|Users\s*$)", _FLAGS),
        "Destructive rm -rf targeting system-critical Windows path",
        "rm_recursive_windows_system_split",
    ),
    # rm --no-preserve-root
    (
        re.compile(r"rm\s+--no-preserve-root", _FLAGS),
        "rm with --no-preserve-root flag",
        "rm_no_preserve_root",
    ),
    # Pipe-to-shell (remote code execution)
    (
        re.compile(
            r"(curl|wget|fetch)\s.*\|\s*(bash|sh|zsh|powershell|pwsh|cmd)", _FLAGS
        ),
        "Pipe-to-shell: downloading and executing remote code",
        "pipe_to_shell",
    ),
    # Pipe-to-source
    (
        re.compile(r"(curl|wget).*\|\s*source", _FLAGS),
        "Pipe-to-source: downloading and sourcing remote code",
        "pipe_to_source",
    ),
    # Execution forms that skip the
    # download-pipe shape: decode-then-execute, and process substitution.
    # ReDoS-safe: the two former unbounded `.*` gaps are bounded
    # to `[^|]*` (a shell-pipe segment can't contain a `|`), so the engine
    # cannot backtrack across the pipe — linear time on adversarial input.
    (
        re.compile(
            r"(base64\s+(-d|--decode)|openssl\s+enc\s+[^|]*-d)[^|]*\|\s*(bash|sh|zsh|powershell|pwsh)",
            _FLAGS,
        ),
        "Decode-and-execute pipeline (obfuscated remote/embedded code)",
        "decode_and_execute",
    ),
    (
        re.compile(r"(bash|sh|zsh)\s+<\(\s*(curl|wget|fetch)", _FLAGS),
        "Executing remote code via process substitution",
        "exec_process_substitution",
    ),
    # Encoded PowerShell
    (
        re.compile(r"powershell.*-[eE]nc(odedCommand)?", _FLAGS),
        "Encoded PowerShell command (potential obfuscation)",
        "powershell_encoded",
    ),
    # Fork bomb — whitespace-tolerant: the classic
    # ``:(){ :|:&};:`` is routinely written with spaces (``:(){ :|:& };:``,
    # ``:(){ : | :&};:``); a fixed-string match missed every spaced variant.
    # Disjoint classes only (``\s`` between fixed tokens), so it stays linear.
    # Mirrored in tests/bash-guard.sh.
    (
        re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.ASCII),
        "Fork bomb detected",
        "fork_bomb",
    ),
    # Credential exfiltration via network tools.
    # Hardening fix (2026-06-08): the previous pattern `\$[A-Z_]*`
    # missed the `${BRACE}` form (e.g. `${API_TOKEN}`). The `$` is followed by
    # `{`, so `[A-Z_]*` never matched. `${VAR}` is an extremely common shell form,
    # making this a realistic bypass. Patch: `\$\{?[A-Z_]*` covers both `$VAR`
    # and `${VAR}`. Mirrored in tests/bash-guard.sh fixture (bash/Python equivalence).
    # Rewritten from a single
    # `tool.*flag.*var` regex (quadratic backtracking -> hook-timeout DoS on
    # long commands) to a staged linear search with identical match semantics.
    (
        _LineStagedSearch(
            r"(curl|wget|nc|ncat)\s",
            r"(-d|--data)",
            r"\$\{?[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD|CRED)",
        ),
        "Potential credential exfiltration via network",
        "cred_exfil_network",
    ),
    # Credential-FILE exfiltration: the env-var form above was RED
    # while uploading the key FILE itself was only ask/allow. Upload flags with
    # a secret-looking source, and secret-file pipes into network tools.
    (
        _LineStagedSearch(
            r"(curl|wget|nc|ncat)\s",
            r"(-d\s*@|--data(-binary)?\s*@|-T\s|--upload-file\s|--post-file=)",
            r"(\.pem|\.key|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.ssh/|\.aws/|\.env\b|credentials|secrets|token)",
        ),
        "Uploading a credential/secret file to the network",
        "cred_file_upload",
    ),
    (
        _LineStagedSearch(
            r"(\.ssh/|\.pem\b|\.key\b|id_rsa|id_ed25519|\.aws/|\.env\b|credentials|secrets)",
            r"\|\s*(nc|ncat|curl|wget)\s",
        ),
        "Piping a local secret file to a network tool",
        "cred_file_pipe_network",
    ),
    # Disk format — note: bash source used `mkfs\s` which missed `mkfs.ext4` (variant
    # filesystem types). `mkfs(\.|\s)` covers `mkfs `, `mkfs.ext4`, `mkfs.btrfs`, etc.
    # Anchored to command position: `grep mkfs log`
    # and `cat mkfs.notes` must not deny — only mkfs at the start of a (sub)command,
    # optionally behind sudo.
    (
        re.compile(_CMD_START + r"(sudo\s+)?mkfs(\.|\s)", _FLAGS_ML),
        "Disk format operation detected",
        "disk_format_mkfs",
    ),
    (
        re.compile(_CMD_START + r"(sudo\s+)?(format\s+[a-z]:|wipefs\s)", _FLAGS_ML),
        "Disk format/wipe operation detected (Windows-native or wipefs form)",
        "disk_format_wipe",
    ),
    # Raw disk write — target list instead of bare `/dev/` (fix:
    # `of=/dev/null` is a sink idiom, not a disk write), command-position anchored.
    # `[^\n|]*` (not `.*`) bounds the if=…of= gap to a single command segment —
    # linear, and keeps the match on one line for re.MULTILINE parity with bash.
    (
        re.compile(
            _CMD_START + r"(sudo\s+)?dd\s+if=[^\n|]*of=/dev/(sd|hd|nvme|mmcblk|vd|xvd|disk|loop)",
            _FLAGS_ML,
        ),
        "Raw disk write operation detected",
        "raw_disk_write",
    ),
    # Write redirect to Windows system directory
    (
        re.compile(r">\s*/c/Windows/", _FLAGS),
        "Write redirect to Windows system directory",
        "write_redirect_windows_system",
    ),
)

# =============================================================================
# YELLOW TIER patterns — Ask user. Suspicious but potentially legitimate.
# =============================================================================
_YELLOW_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    # Broad recursive deletes (caught here only if RED didn't trigger first)
    (
        re.compile(r"rm\s+" + _RM_RF + r"\s", _FLAGS),
        "Recursive force-delete — please confirm target is correct",
    ),
    # Split-flag form of the same: `rm -r -f <target>` off-root
    (
        re.compile(r"rm\s+" + _RM_SPLIT + r"\s", _FLAGS),
        "Recursive force-delete — please confirm target is correct",
    ),
    # Network uploads with file data
    (
        re.compile(
            r"(curl|wget)\s+.*(-X\s*POST|-X\s*PUT|--upload-file|--data-binary\s+@)",
            _FLAGS,
        ),
        "Network upload detected — sending local data to a remote server",
    ),
    # Destructive git operations
    (
        re.compile(
            r"git\s+(push\s+--force|reset\s+--hard|clean\s+-fd)", _FLAGS
        ),
        "Destructive git operation — may lose commit history or untracked files",
    ),
    # Package installation
    (
        re.compile(r"(pip|npm|yarn|pnpm)\s+install\s", _FLAGS),
        "Package installation — confirm this is an approved dependency",
    ),
    # Windows-native / alt recursive-forced deletes: analogs of
    # the YELLOW `rm -rf` tier on the stated target platform.
    (
        re.compile(_CMD_START + r"del\s+/[sq]", _FLAGS_ML),
        "Recursive/forced delete (Windows del) — please confirm target is correct",
    ),
    # Remove-Item -Recurse -Force (either flag order). ReDoS-safe:
    # the former `.*-(recurse.*-force|force.*-recurse)` had nested `.*` in an
    # alternation (quadratic on a long line). Two zero-width lookaheads with
    # line-bounded `[^\n]*` gaps are linear and order-independent.
    (
        re.compile(
            r"remove-item\b(?=[^\n]*-recurse)(?=[^\n]*-force)",
            _FLAGS,
        ),
        "Recursive forced Remove-Item — please confirm target is correct",
    ),
    (
        re.compile(_CMD_START + r"(sudo\s+)?shred\s", _FLAGS_ML),
        "Secure-delete tool — destroys file contents irrecoverably",
    ),
    # World-writable permissions: widened to cover
    # `-R`/split/verbose flags and octal `0777`, and command-anchored so an
    # `echo chmod 777` arg is not flagged. Mirrored in tests/bash-guard.sh.
    (
        re.compile(
            _CMD_START + r"(sudo\s+)?chmod\s+(-[a-zA-Z]+\s+)*[0-7]?777\b",
            _FLAGS_ML,
        ),
        "Setting world-writable permissions (777)",
    ),
    # Windows registry edits
    (
        re.compile(r"(reg\s+(add|delete)|regedit)", _FLAGS),
        "Windows registry modification",
    ),
    # Service/process manipulation
    (
        re.compile(r"(net\s+stop|taskkill|sc\s+delete)", _FLAGS),
        "System service/process manipulation",
    ),
    # Disabling the agent-shield runtime guard — must never be silent.
    # Matches the console script and the real module form, even when wrapped
    # inside bash -c / eval / xargs or quoted. Tolerates interspersed options
    # (e.g. ``--project DIR``) between the program name and ``disable``.
    # Disabling the agent-shield runtime guard — must never be silent.
    # Uses a single contiguous regex (not staged search) to keep Python/bash
    # parity exact: the program must be at command position, followed by option
    # tokens, then the literal subcommand ``disable``. Quoted subcommands and
    # common interpreter spellings (python3.11, python.exe, py) are caught.
    (
        re.compile(
            _CMD_START
            + r"(agent-shield-plugin|(python(?:3(\.\d+)?|\.exe)?|py)\s+-m\s+agent_shield\.plugin_cli)\s+"
            + r"(?:\S+\s+)*['\"]?disable['\"]?\b",
            _FLAGS_ML,
        ),
        "Disabling agent-shield runtime guard — confirm intentional",
    ),
)


def check_command(cmd: str) -> GuardResult:
    """Check a Bash command and return a GuardResult.

    Args:
        cmd: The raw command string (as passed to a Bash interpreter).

    Returns:
        GuardResult with decision in {"deny", "ask", "allow"}.

    Parse-failure behavior:
        If ``cmd`` is empty or None, returns ``allow`` (matches bash version's
        defensive default — never block on parse errors).
    """
    if not cmd:
        return GuardResult(decision="allow")

    if len(cmd) > _MAX_INPUT_CHARS:
        return GuardResult(
            decision="ask",
            reason="Command exceeds the size cap and was not fully evaluated — confirm manually",
        )

    # RED tier — hard block (first match wins)
    for pattern, reason, _pattern_id in _RED_PATTERNS:
        if pattern.search(cmd):
            return GuardResult(decision="deny", reason=reason)

    # YELLOW tier — ask user (first match wins)
    for pattern, reason in _YELLOW_PATTERNS:
        if pattern.search(cmd):
            return GuardResult(decision="ask", reason=reason)

    # GREEN tier — allow silently
    return GuardResult(decision="allow")


def is_red(cmd: str) -> tuple[bool, str]:
    """Return whether ``cmd`` hits a RED pattern, with its ``pattern_id``.

    Reuses ``_RED_PATTERNS`` (the single source of truth) with the SAME
    first-match-wins order as :func:`check_command`, so the reported
    ``pattern_id`` always identifies the entry that ``check_command`` would
    deny on.

    Returns:
        ``(True, pattern_id)`` on the first RED match, else ``(False, "")``.
        Empty/None or over-cap input is treated as not-RED (``(False, "")``) —
        consistent with the never-block-on-parse-error default; the size cap is
        a ``check_command`` concern (this helper is a thin RED-only probe).
    """
    if not cmd or len(cmd) > _MAX_INPUT_CHARS:
        return (False, "")
    for pattern, _reason, pattern_id in _RED_PATTERNS:
        if pattern.search(cmd):
            return (True, pattern_id)
    return (False, "")


def is_red_or_over_cap(cmd: str) -> tuple[bool, str]:
    """Error-path RED probe: fail-closed on over-cap input.

    On the normal evaluation path ``is_red`` correctly returns ``(False, "")``
    for over-cap input because ``check_command`` already short-circuits to
    ``ask``. On the *error* path, however, we cannot evaluate at all, so an
    oversized catastrophic command would otherwise fall through to the policy
    tier (a fail-open hole for ``observe`` / ``open``). This wrapper treats any
    input over ``_MAX_INPUT_CHARS`` as RED-by-default.

    Returns:
        ``(True, "over_cap")`` if ``len(cmd) > _MAX_INPUT_CHARS``; otherwise
        delegates to :func:`is_red`.
    """
    if len(cmd) > _MAX_INPUT_CHARS:
        return (True, "over_cap")
    return is_red(cmd)


def _run_red_only(command: str) -> int:
    """``--red-only`` sub-mode: print ``{"red": bool, "pattern_id": str}``.

    A library/CI probe that exposes the RED verdict alone (no YELLOW/GREEN,
    no hook JSON). Always returns 0 — same never-crash contract as the hook
    path.
    """
    red, pattern_id = is_red(command)
    sys.stdout.write(json.dumps({"red": red, "pattern_id": pattern_id}))
    return 0


def _extract_command_from_hook_input(input_text: str) -> str:
    """Extract the command from Claude Code PreToolUse hook stdin JSON.

    Expected shape: {"tool_name": "Bash", "tool_input": {"command": "..."}}.
    Total function: any malformed shape — non-dict top level,
    non-dict tool_input, non-string command — returns "" instead of raising.
    Pre-fix, a top-level list/null or a non-string command crashed main()
    with exit 1, so the command was never evaluated (silent bypass).
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
    cmd = tool_input.get("command")
    return cmd if isinstance(cmd, str) else ""


def _decode_stdin_bytes(raw: bytes) -> str:
    """Decode hook stdin defensively.

    Windows pipelines (PowerShell in particular) commonly emit UTF-8-BOM or
    UTF-16; a strict utf-8 text read raised UnicodeDecodeError on the stated
    target platform — crash, command never evaluated. BOM-sniff UTF-16,
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
    the command would proceed unevaluated — so the contract is enforced with
    a top-level catch-all. Documented limitation: input that cannot be parsed
    cannot be evaluated and is therefore allowed, matching the bash source's
    parse-failure default.
    """
    try:
        if argv and "--red-only" in argv:
            # --red-only <command>: emit only the RED verdict + pattern_id.
            # The next positional (first non-flag token after --red-only) is the
            # command; a missing positional yields the not-RED verdict (no crash).
            rest = argv[argv.index("--red-only") + 1:]
            command = next((tok for tok in rest if not tok.startswith("-")), "")
            return _run_red_only(command)
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
            cmd = _extract_command_from_hook_input(stdin_text)
            result = claude_code.decide({"tool_name": "Bash", "tool_input": {"command": cmd}})
        hook_json = result.to_hook_json()
        if hook_json is not None:
            # Default json.dumps (ensure_ascii=True) keeps the output ASCII-safe
            # on any console codepage; reasons with em-dashes round-trip as \uXXXX.
            sys.stdout.write(json.dumps(hook_json))
    except Exception:  # noqa: BLE001 — guard contract: never crash
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
