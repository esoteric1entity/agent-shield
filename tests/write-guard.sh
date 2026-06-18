#!/bin/bash

# Force an ASCII-only locale so grep's \s / [[:space:]] never match
# Unicode whitespace — under a UTF-8 locale GNU grep would, diverging from the
# Python port's re.ASCII. LC_ALL=C keeps both ports ASCII-only and decision-
# equivalent in any host locale.
export LC_ALL=C

# =============================================================================
# write-guard.sh — PreToolUse hook for Write/Edit operations
# =============================================================================
# Purpose: Guards sensitive configuration files from accidental modification
# Tiers:
#   RED (deny)  — Claude's own security infrastructure -> hard block
#   YELLOW (ask) — Important configs, agent templates -> prompt the user
#   GREEN (allow) — Everything else -> silent pass
#
# Receives JSON on stdin: {"tool_name":"Write","tool_input":{"file_path":"..."}}
# No hard jq dependency. Runs in pure bash when no interpreter is present
# (degraded: resolves '//' and '/./' but not '..'); uses Python when available
# for full path-normalization parity with agent_shield/write_guard.py.
# =============================================================================

# Patched 2026-06-06: original used a hardcoded Windows-only Python path.
# Now tries portable Python interpreters in order.
# Each candidate is now VALIDATED by executing
# it. `command -v python3` succeeds on stock Windows via the Microsoft Store
# alias, which then errors at runtime -> extraction silently returned empty
# -> every write was allowed. `py` (Windows launcher) added as a fallback.

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
# UTF-8 worst case in agent_shield/write_guard.py.
if [ "${#INPUT}" -gt 4000000 ]; then
    echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"write-guard: input exceeds the size cap — confirm manually\"}}"
    exit 0
fi

# Extract the file_path AND normalize it.
# When Python is present we run the SAME normalization as
# agent_shield/write_guard.py (_normalize_path + _collapse_segments) so both
# ports are byte-for-byte decision-equivalent on every spelling — incl. '//',
# '/./', and '..'. When no interpreter resolves we fall back to a sed extraction
# + a SIMPLER collapse that resolves '//' and '/./' but NOT '..' (documented
# degraded limitation; still strictly better than the prior behavior
# that leaked even '//'). The degraded sed runs the collapse BEFORE the ADS-strip
# to mirror the Python order (collapse -> ADS-strip -> trailing-strip).
# Mirrored in agent_shield/write_guard.py _normalize_path / _collapse_segments.
if [ -n "$PYTHON_BIN" ]; then
    NORM_PATH=$(printf '%s' "$INPUT" | "$PYTHON_BIN" -c '
import sys, json, re
def norm(fp):
    n = fp.replace(chr(92), "/").lower()
    drive = ""
    if len(n) >= 2 and n[1] == ":" and n[0].isalpha():
        drive, n = n[:2], n[2:]
    rooted = n.startswith("/")
    out = []
    for seg in n.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not rooted:
                out.append("..")
            continue
        seg = re.sub(r"[\s.]+$", "", seg, flags=re.ASCII)
        if seg:
            out.append(seg)
    n = ("/" if rooted else "") + "/".join(out)
    slash = n.rfind("/")
    head, base = (n[:slash+1], n[slash+1:]) if slash >= 0 else ("", n)
    base = base.split(":", 1)[0]
    n = drive + head + base
    return re.sub(r"[\s.]+$", "", n, flags=re.ASCII)
try:
    data = json.load(sys.stdin)
    fp = data.get("tool_input", {}).get("file_path", "")
    print(norm(fp) if isinstance(fp, str) else "")
except Exception:
    print("")
' 2>/dev/null)
    # Allow on empty/parse-error (don't block on bad input).
    [ -z "$NORM_PATH" ] && exit 0
else
    # Degraded fallback (no Python): rough sed extraction + simpler normalization.
    FILE_PATH=$(printf '%s' "$INPUT" | sed -n 's/.*"file_path"\s*:\s*"\([^"]*\)".*/\1/p' | head -1)
    [ -z "$FILE_PATH" ] && exit 0
    NORM_PATH=$(printf '%s' "$FILE_PATH" \
        | sed -e 's|\\|/|g' \
              -e 's|^\([a-zA-Z]\):|\1\x01|' \
              -e ':a' -e 's|//|/|g' -e 'ta' \
              -e ':b' -e 's|/\./|/|g' -e 'tb' \
              -e 's|/\.$||' -e 's|^\./||' \
              -e 's|:[^/]*$||' \
              -e 's|\x01|:|' \
              -e 's|[[:space:].]*$||' \
        | tr '[:upper:]' '[:lower:]')
fi

# Degraded mode: the no-Python sed normalizer does NOT resolve
# '..', so a path with a '..' segment could resolve to a guarded file yet miss
# the $-anchored RED patterns. Fail CLOSED (ask) on any '..' segment when running
# without an interpreter; the Python path resolves '..' correctly and is unaffected.
if [ -z "$PYTHON_BIN" ]; then
    case "$NORM_PATH" in
        ..|../*|*/..|*/../*)
            echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"write-guard: path contains '..' and cannot be safely resolved without Python — confirm manually\"}}"
            exit 0 ;;
    esac
fi

# =============================================================================
# RED TIER — Hard block. Claude should NEVER modify its own security config.
# =============================================================================
BLOCK_REASON=""

# The hooks themselves (self-modification attack vector).
# Also protect the canonical Python
# package files. The previous pattern only matched the legacy `hooks/scripts/*.sh`
# deployment, leaving `agent_shield/*.py` (the canonical guards) UNPROTECTED.
# The `(^|/)` prefix covers both vendored (`agent_shield/...`) and site-packages
# install layouts. Mirrored in agent_shield/write_guard.py _RED_PATTERNS.
if echo "$NORM_PATH" | grep -qE '(^|/)agent_shield/(bash_guard|write_guard|_result|__init__)\.py$'; then
    BLOCK_REASON="Cannot modify active agent-shield guard module (self-modification attack vector)"

# The hooks themselves (self-modification attack vector)
elif echo "$NORM_PATH" | grep -qE 'hooks/scripts/(bash-guard|write-guard)\.sh$'; then
    BLOCK_REASON="Cannot modify active security hook scripts"

# Claude's settings files (hook/permission configs live here)
elif echo "$NORM_PATH" | grep -qE '\.claude/settings\.json$'; then
    BLOCK_REASON="Cannot modify Claude settings.json (contains hook/permission configs)"
elif echo "$NORM_PATH" | grep -qE '\.claude/settings\.local\.json$'; then
    BLOCK_REASON="Cannot modify Claude settings.local.json (contains hook/permission configs)"

# SSH private keys — unambiguously secret (id_rsa/id_ed25519/…), so a hard
# block has no false positives. (Generic .pem/.key is YELLOW, not RED — those
# extensions are content-blind: fullchain.pem is a public cert, .key is also
# Keynote's doc type.) Mirrored in
# agent_shield/write_guard.py.
elif echo "$NORM_PATH" | grep -qE '(^|/)\.ssh/id_[a-z0-9_]+$'; then
    BLOCK_REASON="Cannot overwrite SSH private key"

# OpenClaw environment file (per-provider API keys) — same class as
# .claude/settings.json: the agent's own credential surface.
elif echo "$NORM_PATH" | grep -qE '\.openclaw/\.env$'; then
    BLOCK_REASON="Cannot modify .openclaw/.env (agent API credentials)"
fi

if [ -n "$BLOCK_REASON" ]; then
    echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"BLOCKED by write-guard: $BLOCK_REASON\"}}"
    exit 0
fi

# =============================================================================
# YELLOW TIER — Ask the user. Important but sometimes legitimate to modify.
# =============================================================================
ASK_REASON=""

# agent-shield policy config (Layer 7) — editing changes the agent's own security
# policy; config is NOT a trust boundary. ASK (not deny): the file is user-edited.
# Two default basenames; a non-default $AGENT_SHIELD_CONFIG location is unguardable
# by a static matcher (documented limitation). Mirrored in
# agent_shield/write_guard.py _YELLOW_PATTERNS.
if echo "$NORM_PATH" | grep -qE '(^|/)agent-shield\.toml$'; then
    ASK_REASON="Modifying agent-shield policy config — confirm intentional (config is not a trust boundary)"
elif echo "$NORM_PATH" | grep -qE '(^|/)\.agent-shield/config\.toml$'; then
    ASK_REASON="Modifying agent-shield policy config — confirm intentional (config is not a trust boundary)"

# Agent templates (Sentinel, Vault, Clerk definitions)
elif echo "$NORM_PATH" | grep -qEi 'agents/.*\.md$'; then
    ASK_REASON="Modifying agent template — confirm this change is intentional"

# Orchestration rules
elif echo "$NORM_PATH" | grep -qEi '\.claude/rules/.*\.md$'; then
    ASK_REASON="Modifying orchestration rules — confirm this change is intentional"

# Other hook scripts (not the guards themselves)
elif echo "$NORM_PATH" | grep -qEi 'hooks/scripts/.*\.(sh|js|py)$'; then
    ASK_REASON="Modifying hook script — confirm this change is intentional"

# Memory files (Vault's domain)
elif echo "$NORM_PATH" | grep -qEi '/memory/.*\.md$'; then
    ASK_REASON="Modifying memory file — should this go through Vault instead?"

# Environment and credentials files
elif echo "$NORM_PATH" | grep -qEi '\.(env|env\.local|env\.production)$'; then
    ASK_REASON="Modifying environment file — may contain secrets"

# Shell startup files — persistence vector; ask, not deny
elif echo "$NORM_PATH" | grep -qE '(^|/)\.(bashrc|bash_profile|bash_login|bash_logout|zshrc|zprofile|profile)$'; then
    ASK_REASON="Modifying shell startup file — common persistence vector; confirm intentional"
elif echo "$NORM_PATH" | grep -qEi '(credentials|secrets|tokens|passwords)\.(json|yaml|yml|toml|ini|txt)$'; then
    ASK_REASON="Modifying file that may contain credentials"

# Key/cert files by extension — ask, not deny (content-blind: fullchain.pem is
# a public cert, .key is also Keynote's doc type). SSH id_* keys stay RED above.
elif echo "$NORM_PATH" | grep -qEi '\.(pem|key)$'; then
    ASK_REASON="Modifying a .pem/.key file — confirm this isn't a private key you meant to keep"

# CLAUDE.md instruction files
elif echo "$NORM_PATH" | grep -qEi 'claude\.md$'; then
    ASK_REASON="Modifying CLAUDE.md instruction file — affects Claude behavior"

# Sync protocol files — (^|/) boundary keeps dirnames like mysync/ from matching
elif echo "$NORM_PATH" | grep -qEi '(^|/)(claude_)?sync/.*\.md$'; then
    ASK_REASON="Modifying sync protocol file — affects cross-instance communication"
fi

if [ -n "$ASK_REASON" ]; then
    echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"write-guard: $ASK_REASON\"}}"
    exit 0
fi

# =============================================================================
# GREEN TIER — Allow silently
# =============================================================================
exit 0
