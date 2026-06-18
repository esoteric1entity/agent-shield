#!/bin/bash

# Force an ASCII-only locale so grep's \s / [[:space:]] never match
# Unicode whitespace (NBSP, ideographic space, …). Under a UTF-8 locale GNU grep
# WOULD match them, diverging from the Python port's re.ASCII. LC_ALL=C makes both
# ports ASCII-only and decision-equivalent in ANY host locale (the production
# default on Linux/macOS is UTF-8, where the hooks actually run).
export LC_ALL=C

# =============================================================================
# bash-guard.sh — PreToolUse hook for Bash commands
# =============================================================================
# Purpose: Runtime security guard that checks Bash commands before execution
# Tiers:
#   RED (deny)  — Catastrophic/destructive patterns -> hard block
#   YELLOW (ask) — Suspicious patterns -> prompt the user for confirmation
#   GREEN (allow) — Everything else -> silent pass
#
# Receives JSON on stdin: {"tool_name":"Bash","tool_input":{"command":"..."}}
# Uses pure bash — no jq or python dependency
# =============================================================================

# Patched 2026-06-06: original used a hardcoded Windows-only Python path.
# Now tries portable Python interpreters in order; falls back to sed only when
# no Python is available. (The sed fallback has a known limitation with escaped
# quotes inside JSON strings — see test case: credential-exfil with $API_TOKEN.)

# Find a working Python interpreter.
# Each candidate is now VALIDATED by executing
# it. `command -v python3` succeeds on stock Windows via the Microsoft Store
# alias, which then errors at runtime -> extraction silently returned empty
# -> every command was allowed. `py` (Windows launcher) added as a fallback.
PYTHON_BIN=""
for candidate in python3 python py; do
    if "$candidate" -c 'pass' > /dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

# Read all stdin
INPUT=$(cat)

# Input-size cap: mirror the Python main() read cap —
# an oversized payload short-circuits to a conservative `ask` (never silent allow)
# so the guard can't be stalled into a hook timeout. ~4M bytes = the 1M-char cap's
# UTF-8 worst case in agent_shield/bash_guard.py.
if [ "${#INPUT}" -gt 4000000 ]; then
    echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"bash-guard: input exceeds the size cap — confirm manually\"}}"
    exit 0
fi

# Extract the command field
if [ -n "$PYTHON_BIN" ]; then
    CMD=$(echo "$INPUT" | "$PYTHON_BIN" -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_input', {}).get('command', ''))
except:
    print('')
" 2>/dev/null)
else
    # Fallback: rough extraction with sed (handles simple cases only;
    # does NOT correctly handle escaped quotes inside JSON strings)
    CMD=$(echo "$INPUT" | sed -n 's/.*"command"\s*:\s*"\([^"]*\)".*/\1/p' | head -1)
fi

# Cap the EXTRACTED command to match the Python port's check_command
# _MAX_INPUT_CHARS (1M chars), so a 1M-4M-char command short-circuits to `ask` in
# BOTH ports (the outer INPUT byte-cap only catches >4M raw). Conservative; never allow.
if [ "${#CMD}" -gt 1000000 ]; then
    echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"bash-guard: command exceeds the size cap — confirm manually\"}}"
    exit 0
fi

# Fail-closed hardening: when no Python is available,
# the sed fallback can truncate at the first escaped quote — which is exactly
# where credential-exfil commands live. The RED patterns below are unanchored,
# so when extraction is degraded we scan the RAW hook JSON as well: a RED
# match anywhere in the input still denies. YELLOW stays on the extracted
# command only (avoids over-asking on JSON syntax).
SCAN_TEXT="$CMD"
if [ -z "$PYTHON_BIN" ]; then
    SCAN_TEXT="$CMD
$INPUT"
fi

# If we couldn't parse the command and have nothing to scan, allow
# (don't block on parse errors)
if [ -z "$CMD" ] && [ -n "$PYTHON_BIN" ]; then
    exit 0
fi
if [ -z "$CMD" ] && [ -z "$INPUT" ]; then
    exit 0
fi

# Command-position prefix for destructive *verbs* (mkfs/dd/format/del/shred).
# Mirrors agent_shield/bash_guard.py _CMD_START: line start OR after a shell
# separator, then optional leading whitespace + env-var assignments
# (`   dd …`, `FOO=1 dd …`). grep is already per-line (so `^` = each line);
# this just closes the leading-ws / env-var evasion for py↔bash parity.
# Also treat a shell-invocation / eval / xargs
# lead-in as a command introducer (mirrors _SHELL_INTRO in bash_guard.py) so a
# destructive verb inside `bash -c '…'`, `eval …`, or `xargs …` is at command
# position even though no ^/;/&/| precedes it.
SHELL_INTRO='((bash|sh|zsh|dash|ash)[[:space:]]+(-{1,2}[^[:space:]]+[[:space:]]+)*-[a-zA-Z]*c[[:space:]]+["'\'']?|eval[[:space:]]+["'\'']?|xargs[[:space:]]+(-[^[:space:]]+[[:space:]]+([^-[:space:]][^[:space:]]*[[:space:]]+)?)*)'
CMD_START="(^|[;&|]|${SHELL_INTRO})[[:space:]]*(\w+=\S*[[:space:]]+)*"

# =============================================================================
# RED TIER — Hard block. Catastrophic/destructive patterns.
# =============================================================================
BLOCK_REASON=""

# Destructive rm targeting critical paths
# (RED greps scan $SCAN_TEXT: the extracted command, plus the raw hook JSON
#  when no Python is available — see fail-closed hardening note above.)
if echo "$SCAN_TEXT" | grep -qEi 'rm\s+-([a-z]{0,12}r[a-z]{0,12}f[a-z]{0,12}|[a-z]{0,12}f[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*/([[:space:];&|<>)'\''"]|$|\*)'; then
    BLOCK_REASON="Destructive rm -rf targeting root directory"

# Cheap literal evasions: quoted root,
# split flags, home/cwd targets. Mirrored in agent_shield/bash_guard.py.
elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+-([a-z]{0,12}r[a-z]{0,12}f[a-z]{0,12}|[a-z]{0,12}f[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*["'\'']/["'\'']'; then
    BLOCK_REASON="Destructive rm -rf targeting root directory (quoted)"
elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+(-[a-z]{0,12}r[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}f[a-z]{0,12}|-[a-z]{0,12}f[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*/([[:space:];&|<>)'\''"]|$|\*)'; then
    BLOCK_REASON="Destructive rm -rf targeting root directory (split flags)"
elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+-([a-z]{0,12}r[a-z]{0,12}f[a-z]{0,12}|[a-z]{0,12}f[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*(~|\$HOME)/?([[:space:];&|<>)]|$)'; then
    BLOCK_REASON="Destructive rm -rf targeting home directory"
elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+-([a-z]{0,12}r[a-z]{0,12}f[a-z]{0,12}|[a-z]{0,12}f[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*\.\.?([[:space:];&|<>)]|$)'; then
    BLOCK_REASON="Destructive rm -rf targeting current/parent directory"

elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+-([a-z]{0,12}r[a-z]{0,12}f[a-z]{0,12}|[a-z]{0,12}f[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*/c/(Windows|Program|Users\s*$)'; then
    BLOCK_REASON="Destructive rm -rf targeting system-critical Windows path"
# Split-flag form (rm -r -f / -rv -f) at the non-root critical targets — mirrors
# the single-token patterns so RED coverage is uniform across spellings.
elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+(-[a-z]{0,12}r[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}f[a-z]{0,12}|-[a-z]{0,12}f[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*["'\'']/["'\'']'; then
    BLOCK_REASON="Destructive rm -rf targeting root directory (quoted)"
elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+(-[a-z]{0,12}r[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}f[a-z]{0,12}|-[a-z]{0,12}f[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*(~|\$HOME)/?([[:space:];&|<>)]|$)'; then
    BLOCK_REASON="Destructive rm -rf targeting home directory"
elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+(-[a-z]{0,12}r[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}f[a-z]{0,12}|-[a-z]{0,12}f[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*\.\.?([[:space:];&|<>)]|$)'; then
    BLOCK_REASON="Destructive rm -rf targeting current/parent directory"
elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+(-[a-z]{0,12}r[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}f[a-z]{0,12}|-[a-z]{0,12}f[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}r[a-z]{0,12})\s+(-{1,2}\S+\s+)*/c/(Windows|Program|Users\s*$)'; then
    BLOCK_REASON="Destructive rm -rf targeting system-critical Windows path"
elif echo "$SCAN_TEXT" | grep -qEi 'rm\s+--no-preserve-root'; then
    BLOCK_REASON="rm with --no-preserve-root flag"

# Pipe-to-shell (remote code execution)
elif echo "$SCAN_TEXT" | grep -qEi '(curl|wget|fetch)\s.*\|\s*(bash|sh|zsh|powershell|pwsh|cmd)'; then
    BLOCK_REASON="Pipe-to-shell: downloading and executing remote code"
elif echo "$SCAN_TEXT" | grep -qEi '(curl|wget).*\|\s*source'; then
    BLOCK_REASON="Pipe-to-source: downloading and sourcing remote code"

# Execution forms that skip the
# download-pipe shape: decode-then-execute, process substitution.
elif echo "$SCAN_TEXT" | grep -qEi '(base64\s+(-d|--decode)|openssl\s+enc\s+[^|]*-d)[^|]*\|\s*(bash|sh|zsh|powershell|pwsh)'; then
    BLOCK_REASON="Decode-and-execute pipeline (obfuscated remote/embedded code)"
elif echo "$SCAN_TEXT" | grep -qEi '(bash|sh|zsh)\s+<\(\s*(curl|wget|fetch)'; then
    BLOCK_REASON="Executing remote code via process substitution"

# Encoded/obfuscated execution
elif echo "$SCAN_TEXT" | grep -qEi 'powershell.*-[eE]nc(odedCommand)?'; then
    BLOCK_REASON="Encoded PowerShell command (potential obfuscation)"

# Fork bomb — whitespace-tolerant: the classic
# bomb is routinely spaced (`:(){ :|:& };:`, `:(){ : | :&};:`); the old -qF
# fixed-string missed every spaced variant. Mirrors bash_guard.py.
elif echo "$SCAN_TEXT" | grep -qE ':[[:space:]]*\([[:space:]]*\)[[:space:]]*\{[[:space:]]*:[[:space:]]*\|[[:space:]]*:[[:space:]]*&[[:space:]]*\}[[:space:]]*;[[:space:]]*:'; then
    BLOCK_REASON="Fork bomb detected"

# Credential exfiltration via network tools.
# `\$[A-Z_]*` missed the `${BRACE}` form.
# Patch: `\$\{?[A-Z_]*` covers both `$VAR` and `${VAR}`. Mirrored in
# agent_shield/bash_guard.py _RED_PATTERNS (Python side uses a staged
# linear search for the same semantics — grep's ERE engine is already
# linear, so the single pattern is safe here).
elif echo "$SCAN_TEXT" | grep -qEi '(curl|wget|nc|ncat)\s.*(-d|--data).*(\$\{?[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD|CRED))'; then
    BLOCK_REASON="Potential credential exfiltration via network"

# Credential-FILE exfiltration: upload flags with a secret-looking
# source file, and secret-file pipes into network tools. Mirrored in
# agent_shield/bash_guard.py (staged linear form there; grep ERE is already linear).
elif echo "$SCAN_TEXT" | grep -qEi '(curl|wget|nc|ncat)\s.*(-d\s*@|--data(-binary)?\s*@|-T\s|--upload-file\s|--post-file=).*(\.pem|\.key|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.ssh/|\.aws/|\.env\b|credentials|secrets|token)'; then
    BLOCK_REASON="Uploading a credential/secret file to the network"
elif echo "$SCAN_TEXT" | grep -qEi '(\.ssh/|\.pem\b|\.key\b|id_rsa|id_ed25519|\.aws/|\.env\b|credentials|secrets).*\|\s*(nc|ncat|curl|wget)\s'; then
    BLOCK_REASON="Piping a local secret file to a network tool"

# Disk operations
# Patched 2026-06-06: was `mkfs\s` which missed `mkfs.ext4` (no whitespace after `mkfs`).
# Anchored to command position so
# `grep mkfs log` / `cat mkfs.notes` don't deny; `of=/dev/null` (a sink idiom)
# no longer counts as a disk write — real block-device targets only.
# Windows-native `format X:` and `wipefs` added as RED disk-level verbs.
# See agent_shield/bash_guard.py for the matching Python port.
elif echo "$SCAN_TEXT" | grep -qEi "${CMD_START}(sudo\s+)?mkfs(\.|\s)"; then
    BLOCK_REASON="Disk format operation detected"
elif echo "$SCAN_TEXT" | grep -qEi "${CMD_START}(sudo\s+)?(format\s+[a-z]:|wipefs\s)"; then
    BLOCK_REASON="Disk format/wipe operation detected (Windows-native or wipefs form)"
elif echo "$SCAN_TEXT" | grep -qEi "${CMD_START}(sudo\s+)?dd\s+if=[^|]*of=/dev/(sd|hd|nvme|mmcblk|vd|xvd|disk|loop)"; then
    BLOCK_REASON="Raw disk write operation detected"

# Write to Windows system directory
elif echo "$SCAN_TEXT" | grep -qEi '>\s*/c/Windows/'; then
    BLOCK_REASON="Write redirect to Windows system directory"
fi

if [ -n "$BLOCK_REASON" ]; then
    echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"BLOCKED by bash-guard: $BLOCK_REASON\"}}"
    exit 0
fi

# =============================================================================
# YELLOW TIER — Ask the user. Suspicious but potentially legitimate.
# =============================================================================
ASK_REASON=""

# Broad recursive deletes (not targeting root, but still risky)
if echo "$CMD" | grep -qEi 'rm\s+-([a-z]{0,12}r[a-z]{0,12}f[a-z]{0,12}|[a-z]{0,12}f[a-z]{0,12}r[a-z]{0,12})\s'; then
    ASK_REASON="Recursive force-delete — please confirm target is correct"

# Split-flag form of the same: `rm -r -f <target>` off-root
elif echo "$CMD" | grep -qEi 'rm\s+(-[a-z]{0,12}r[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}f[a-z]{0,12}|-[a-z]{0,12}f[a-z]{0,12}\s+(-{1,2}\S+\s+)*-[a-z]{0,12}r[a-z]{0,12})\s'; then
    ASK_REASON="Recursive force-delete — please confirm target is correct"

# Network uploads with file data
elif echo "$CMD" | grep -qEi '(curl|wget)\s+.*(-X\s*POST|-X\s*PUT|--upload-file|--data-binary\s+@)'; then
    ASK_REASON="Network upload detected — sending local data to a remote server"

# Destructive git operations
elif echo "$CMD" | grep -qEi 'git\s+(push\s+--force|reset\s+--hard|clean\s+-fd)'; then
    ASK_REASON="Destructive git operation — may lose commit history or untracked files"

# Package installation (not just listing)
elif echo "$CMD" | grep -qEi '(pip|npm|yarn|pnpm)\s+install\s'; then
    ASK_REASON="Package installation — confirm this is an approved dependency"

# Windows-native / alt recursive-forced deletes
elif echo "$CMD" | grep -qEi "${CMD_START}del\s+/[sq]"; then
    ASK_REASON="Recursive/forced delete (Windows del) — please confirm target is correct"
elif echo "$CMD" | grep -qEi 'remove-item\s+.*-(recurse.*-force|force.*-recurse)'; then
    ASK_REASON="Recursive forced Remove-Item — please confirm target is correct"
elif echo "$CMD" | grep -qEi "${CMD_START}(sudo\s+)?shred\s"; then
    ASK_REASON="Secure-delete tool — destroys file contents irrecoverably"

# World-writable permissions: cover -R/flags/octal
# 0777 and command-anchor (mirrors bash_guard.py _CMD_START + chmod pattern).
elif echo "$CMD" | grep -qEi "${CMD_START}(sudo\s+)?chmod\s+(-[a-zA-Z]+\s+)*[0-7]?777\b"; then
    ASK_REASON="Setting world-writable permissions (777)"

# Windows registry edits
elif echo "$CMD" | grep -qEi '(reg\s+(add|delete)|regedit)'; then
    ASK_REASON="Windows registry modification"

# Service/process manipulation
elif echo "$CMD" | grep -qEi '(net\s+stop|taskkill|sc\s+delete)'; then
    ASK_REASON="System service/process manipulation"
fi

if [ -n "$ASK_REASON" ]; then
    echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"bash-guard: $ASK_REASON\"}}"
    exit 0
fi

# =============================================================================
# GREEN TIER — Allow silently
# =============================================================================
exit 0
