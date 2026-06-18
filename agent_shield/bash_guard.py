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
_RED_PATTERNS: Final[tuple[tuple[re.Pattern[str] | _LineStagedSearch, str], ...]] = (
    # Destructive rm targeting root
    (
        # A trailing shell separator/terminator/quote
        # after `/` (`rm -rf /;`, `/&`, `/|cat`, `rm -rf /'`) resolves to root but
        # the old `(\s|$|\*)` tail downgraded it to YELLOW. Mirrored in bash-guard.sh.
        re.compile(r"rm\s+-(rf|fr)\s+/([\s;&|<>)'\"]|$|\*)", _FLAGS),
        "Destructive rm -rf targeting root directory",
    ),
    # Cheap literal evasions of the above:
    # quoted root, split flags, home/cwd targets.
    (
        re.compile(r"""rm\s+-(rf|fr)\s+["']/["']""", _FLAGS),
        "Destructive rm -rf targeting root directory (quoted)",
    ),
    (
        re.compile(r"rm\s+(-r\s+-f|-f\s+-r)\s+/(\s|$|\*)", _FLAGS),
        "Destructive rm -rf targeting root directory (split flags)",
    ),
    (
        re.compile(r"rm\s+-(rf|fr)\s+(~|\$HOME)/?([\s;&|<>)]|$)", _FLAGS),
        "Destructive rm -rf targeting home directory",
    ),
    (
        re.compile(r"rm\s+-(rf|fr)\s+\.\.?([\s;&|<>)]|$)", _FLAGS),
        "Destructive rm -rf targeting current/parent directory",
    ),
    # Destructive rm targeting Windows system paths
    (
        re.compile(r"rm\s+-(rf|fr)\s+/c/(Windows|Program|Users\s*$)", _FLAGS),
        "Destructive rm -rf targeting system-critical Windows path",
    ),
    # rm --no-preserve-root
    (
        re.compile(r"rm\s+--no-preserve-root", _FLAGS),
        "rm with --no-preserve-root flag",
    ),
    # Pipe-to-shell (remote code execution)
    (
        re.compile(
            r"(curl|wget|fetch)\s.*\|\s*(bash|sh|zsh|powershell|pwsh|cmd)", _FLAGS
        ),
        "Pipe-to-shell: downloading and executing remote code",
    ),
    # Pipe-to-source
    (
        re.compile(r"(curl|wget).*\|\s*source", _FLAGS),
        "Pipe-to-source: downloading and sourcing remote code",
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
    ),
    (
        re.compile(r"(bash|sh|zsh)\s+<\(\s*(curl|wget|fetch)", _FLAGS),
        "Executing remote code via process substitution",
    ),
    # Encoded PowerShell
    (
        re.compile(r"powershell.*-[eE]nc(odedCommand)?", _FLAGS),
        "Encoded PowerShell command (potential obfuscation)",
    ),
    # Fork bomb — whitespace-tolerant: the classic
    # ``:(){ :|:&};:`` is routinely written with spaces (``:(){ :|:& };:``,
    # ``:(){ : | :&};:``); a fixed-string match missed every spaced variant.
    # Disjoint classes only (``\s`` between fixed tokens), so it stays linear.
    # Mirrored in tests/bash-guard.sh.
    (
        re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.ASCII),
        "Fork bomb detected",
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
    ),
    (
        _LineStagedSearch(
            r"(\.ssh/|\.pem\b|\.key\b|id_rsa|id_ed25519|\.aws/|\.env\b|credentials|secrets)",
            r"\|\s*(nc|ncat|curl|wget)\s",
        ),
        "Piping a local secret file to a network tool",
    ),
    # Disk format — note: bash source used `mkfs\s` which missed `mkfs.ext4` (variant
    # filesystem types). `mkfs(\.|\s)` covers `mkfs `, `mkfs.ext4`, `mkfs.btrfs`, etc.
    # Anchored to command position: `grep mkfs log`
    # and `cat mkfs.notes` must not deny — only mkfs at the start of a (sub)command,
    # optionally behind sudo.
    (
        re.compile(_CMD_START + r"(sudo\s+)?mkfs(\.|\s)", _FLAGS_ML),
        "Disk format operation detected",
    ),
    (
        re.compile(_CMD_START + r"(sudo\s+)?(format\s+[a-z]:|wipefs\s)", _FLAGS_ML),
        "Disk format/wipe operation detected (Windows-native or wipefs form)",
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
    ),
    # Write redirect to Windows system directory
    (
        re.compile(r">\s*/c/Windows/", _FLAGS),
        "Write redirect to Windows system directory",
    ),
)

# =============================================================================
# YELLOW TIER patterns — Ask user. Suspicious but potentially legitimate.
# =============================================================================
_YELLOW_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    # Broad recursive deletes (caught here only if RED didn't trigger first)
    (
        re.compile(r"rm\s+-(rf|fr)\s", _FLAGS),
        "Recursive force-delete — please confirm target is correct",
    ),
    # Split-flag form of the same: `rm -r -f <target>` off-root
    (
        re.compile(r"rm\s+(-r\s+-f|-f\s+-r)\s", _FLAGS),
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
    for pattern, reason in _RED_PATTERNS:
        if pattern.search(cmd):
            return GuardResult(decision="deny", reason=reason)

    # YELLOW tier — ask user (first match wins)
    for pattern, reason in _YELLOW_PATTERNS:
        if pattern.search(cmd):
            return GuardResult(decision="ask", reason=reason)

    # GREEN tier — allow silently
    return GuardResult(decision="allow")


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
    _ = argv  # not used; reserved for future flags
    try:
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
            cmd = _extract_command_from_hook_input(stdin_text)
            result = check_command(cmd)
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
