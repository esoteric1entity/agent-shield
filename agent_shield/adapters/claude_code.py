"""Claude Code PreToolUse adapter (live).

Input  : a parsed CC PreToolUse event dict
         {"tool_name": "Bash"|"Write"|"Edit"|"MultiEdit", "tool_input": {...}}
Output : a CC hook-response dict (or None == silent allow).

Both this adapter and adapters/openclaw.py call the SAME neutral core, so an
equivalent action yields an identical GuardResult regardless of harness.
"""
from __future__ import annotations

from .. import bash_guard, write_guard
from .._result import GuardResult

_WRITE_TOOLS = {"Write", "Edit", "MultiEdit"}

#: Lazy cache for the loaded config + audit log. The cache is resettable for
#: tests by monkeypatching ``_get_config_and_log`` directly.
_CACHED_CFG = None
_CACHED_AUDIT_LOG = None


def _get_config_and_log():
    """Return ``(cfg, audit_log)`` for this harness.

    Config is loaded once and cached; the ``AuditLog`` instance is cached with
    it so repeated calls stay hot. Tests can monkeypatch this helper with a
    controlled config and temp ``AuditLog``. Imports are function-local to
    avoid eager config file I/O at module import time and to mirror the
    defensive import pattern used by the guards themselves.
    """
    global _CACHED_CFG, _CACHED_AUDIT_LOG
    if _CACHED_CFG is None:
        from .. import audit, config

        _CACHED_CFG = config.load(harness="claude_code")
        _CACHED_AUDIT_LOG = audit.AuditLog(path=_CACHED_CFG.audit.path, preset=_CACHED_CFG.compliance)
    return _CACHED_CFG, _CACHED_AUDIT_LOG


def _record_normal(audit_log, tool: str, raw: str, result: GuardResult, tool_input: dict) -> None:
    """Record a normal-path guard outcome. Audit failures are swallowed by the
    default fail-open preset — the hook response must never depend on logging."""
    from .. import audit

    details = {"reason": result.reason}
    if tool == "Bash":
        audit_log.record(action="bash", target=raw, outcome=result.decision, details=details)
        return

    # Write/Edit/MultiEdit: record_write when content is available; otherwise
    # a plain write record. The CC PreToolUse payload carries "content" for Write
    # and "old_string"/"new_string" for Edit; we only hash when explicit content
    # slots are supplied to avoid extra file I/O on the hot path.
    if "content" in tool_input or "content_after" in tool_input or "content_before" in tool_input:
        content_after = tool_input.get("content_after", tool_input.get("content"))
        audit_log.record_write(
            target=raw,
            outcome=result.decision,
            content_before=tool_input.get("content_before"),
            content_after=content_after,
            details=details,
        )
    else:
        audit_log.record(action="write", target=raw, outcome=result.decision, details=details)


def _resolve_cannot_evaluate(tool: str, raw: str, result: GuardResult) -> GuardResult:
    """Run the error-policy resolver + telemetry for a cannot_evaluate event.

    Returns a terminal ``GuardResult`` (allow/ask/deny) and writes a
    ``guard_unavailable`` audit record. For ``observe`` policy
    ``would-have-blocked`` outcomes, the observe visibility hook is used so the
    per-session stderr banner + counter fire.
    """
    from .._error_policy import resolve_error_policy
    from .._self_lockout_allowlist import check as _self_lockout_check
    from .._telemetry import observe_visibility_hook, record_guard_unavailable

    cfg, audit_log = _get_config_and_log()
    red_check_callable = bash_guard.is_red_or_over_cap if tool == "Bash" else write_guard.is_red_or_over_cap

    try:
        decision, outcome_reason = resolve_error_policy(
            raw=raw,
            error_policy=cfg.guard.error_policy,
            attended=not cfg.guard.unattended,
            trigger=result.trigger or "unknown",
            red_check_callable=red_check_callable,
            self_lockout_checker_callable=_self_lockout_check,
        )
    except Exception as exc:  # noqa: BLE001 — resolver must never crash the hook
        decision, outcome_reason = "deny", "denied-unevaluated"
        # Swallow the audit failure below; the reason string tells the user what happened.

    if outcome_reason == "would-have-blocked":
        try:
            observe_visibility_hook(
                audit_log=audit_log,
                raw=raw,
                trigger=result.trigger or "unknown",
                action_tier=result.action_tier,
                attended=not cfg.guard.unattended,
                error_policy=cfg.guard.error_policy,
                harness="claude_code",
            )
        except Exception:  # noqa: BLE001 — counter/banner is best-effort
            pass
    else:
        try:
            record_guard_unavailable(
                audit_log=audit_log,
                raw=raw,
                trigger=result.trigger or "unknown",
                action_tier=result.action_tier,
                attended=not cfg.guard.unattended,
                error_policy=cfg.guard.error_policy,
                outcome_reason=outcome_reason,
                harness="claude_code",
            )
        except Exception:  # noqa: BLE001 — audit is best-effort
            pass

    if decision == "allow":
        return GuardResult(decision="allow")
    return GuardResult(decision=decision, reason=f"Guard unavailable — {outcome_reason}")


def decide(event: dict) -> GuardResult:
    """Route a CC event to the neutral core. Unknown/missing -> allow (fail-open,
    matching the shipped hook contract: input that cannot be evaluated proceeds)."""
    tool = (event or {}).get("tool_name")
    tool_input = (event or {}).get("tool_input") or {}
    if tool == "Bash":
        cmd = tool_input.get("command")
        raw = cmd if isinstance(cmd, str) else ""
        result = bash_guard.check_command(raw)
        if result.decision == "cannot_evaluate":
            return _resolve_cannot_evaluate(tool, raw, result)
        cfg, audit_log = _get_config_and_log()
        _record_normal(audit_log, tool, raw, result, tool_input)
        return result
    if tool in _WRITE_TOOLS:
        path = tool_input.get("file_path")
        raw = path if isinstance(path, str) else ""
        result = write_guard.check_path(raw)
        if result.decision == "cannot_evaluate":
            return _resolve_cannot_evaluate(tool, raw, result)
        cfg, audit_log = _get_config_and_log()
        _record_normal(audit_log, tool, raw, result, tool_input)
        return result
    return GuardResult(decision="allow")


def format_response(result: GuardResult) -> dict | None:
    """CC PreToolUse response. None == silent allow (no stdout)."""
    return result.to_hook_json()
