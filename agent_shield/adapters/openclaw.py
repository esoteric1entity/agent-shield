"""OpenClaw before_tool_call adapter (functional).

Input  : an OpenClaw before_tool_call event dict
         {"toolName": str, "params": {...}, "derivedPaths"?: [str], ...}
Output : a BeforeToolCallResult dict:
           deny  -> {"block": True, "blockReason": reason}      (terminal deny)
           ask   -> {"requireApproval": {...}}                  (pause + approve)
           allow -> {}                                          (proceed)

Decision logic is the SAME neutral core the Claude Code adapter uses, so an
equivalent action yields an identical GuardResult across harnesses. The harness
error policy defaults to "closed"; unknown or malformed events still proceed
(allow) because the adapter cannot make a safety decision without a command or
path, while the CLI boundary (`main()`) retains its outer fail-open shell for
subprocess-crashes-only, consistent with the TS companion plugin contract.

The thin TypeScript companion plugin (adapters/openclaw_plugin/index.ts) calls
this via subprocess and returns this dict from its before_tool_call handler.
"""
from __future__ import annotations

import json
import sys

from .. import bash_guard, write_guard
from .._result import GuardResult

_PATH_KEYS = ("file_path", "path", "filePath")

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

        _CACHED_CFG = config.load(harness="openclaw")
        _CACHED_AUDIT_LOG = audit.AuditLog(path=_CACHED_CFG.audit.path, preset=_CACHED_CFG.compliance)
    return _CACHED_CFG, _CACHED_AUDIT_LOG


def _record_normal(audit_log, tool_kind: str, raw: str, result: GuardResult, params: dict) -> None:
    """Record a normal-path guard outcome. Audit failures are swallowed by the
    default fail-open preset — the hook response must never depend on logging."""
    details = {"reason": result.reason}
    if tool_kind == "Bash":
        audit_log.record(action="bash", target=raw, outcome=result.decision, details=details)
        return
    if "content" in params or "content_after" in params or "content_before" in params:
        content_after = params.get("content_after", params.get("content"))
        audit_log.record_write(
            target=raw,
            outcome=result.decision,
            content_before=params.get("content_before"),
            content_after=content_after,
            details=details,
        )
    else:
        audit_log.record(action="write", target=raw, outcome=result.decision, details=details)


def _resolve_cannot_evaluate(tool_kind: str, raw: str, result: GuardResult, event: dict) -> GuardResult:
    """Run the error-policy resolver + telemetry for a cannot_evaluate event.

    Returns a terminal ``GuardResult`` (allow/ask/deny) and writes a
    ``guard_unavailable`` audit record. For ``observe`` policy
    ``would-have-blocked`` outcomes, the observe visibility hook is used so the
    per-session stderr banner + counter fire (when a sessionId is provided by the
    TS bridge, the banner is coalesced across subprocess calls).
    """
    from .._error_policy import resolve_error_policy
    from .._self_lockout_allowlist import check as _self_lockout_check
    from .._telemetry import observe_visibility_hook, record_guard_unavailable

    cfg, audit_log = _get_config_and_log()
    red_check_callable = bash_guard.is_red_or_over_cap if tool_kind == "Bash" else write_guard.is_red_or_over_cap
    session_id = (event or {}).get("sessionId") or (event or {}).get("session_id") or (event or {}).get("session")

    try:
        decision, outcome_reason = resolve_error_policy(
            raw=raw,
            error_policy=cfg.guard.error_policy,
            attended=not cfg.guard.unattended,
            trigger=result.trigger or "unknown",
            red_check_callable=red_check_callable,
            self_lockout_checker_callable=_self_lockout_check,
        )
    except Exception:  # noqa: BLE001 — resolver must never crash the hook
        decision, outcome_reason = "deny", "denied-unevaluated"

    if outcome_reason == "would-have-blocked":
        try:
            observe_visibility_hook(
                audit_log=audit_log,
                raw=raw,
                trigger=result.trigger or "unknown",
                action_tier=result.action_tier,
                attended=not cfg.guard.unattended,
                error_policy=cfg.guard.error_policy,
                harness="openclaw",
                session=session_id,
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
                harness="openclaw",
            )
        except Exception:  # noqa: BLE001 — audit is best-effort
            pass

    if decision == "allow":
        return GuardResult(decision="allow")
    return GuardResult(decision=decision, reason=f"Guard unavailable — {outcome_reason}")


def _extract(event: dict) -> tuple[str | None, str | None]:
    """Return (command, path) — at most one is non-None. Best-effort, never raises."""
    params = (event or {}).get("params") or {}
    if not isinstance(params, dict):
        params = {}
    cmd = params.get("command")
    if isinstance(cmd, str):
        return cmd, None
    for key in _PATH_KEYS:
        if isinstance(params.get(key), str):
            return None, params[key]
    derived = (event or {}).get("derivedPaths")
    if isinstance(derived, list) and derived and isinstance(derived[0], str):
        return None, derived[0]
    return None, None


def decide(event: dict) -> GuardResult:
    """Route an OpenClaw event to the neutral core. Unknown/missing -> allow."""
    params = (event or {}).get("params") or {}
    if not isinstance(params, dict):
        params = {}
    cmd, path = _extract(event)
    result = GuardResult(decision="allow")
    if cmd is not None:
        result = bash_guard.check_command(cmd)
        if result.decision == "cannot_evaluate":
            result = _resolve_cannot_evaluate("Bash", cmd, result, event)
        else:
            try:
                cfg, audit_log = _get_config_and_log()
                _record_normal(audit_log, "Bash", cmd, result, params)
            except Exception:  # noqa: BLE001 — audit failure must not break the hook
                pass
    elif path is not None:
        result = write_guard.check_path(path)
        if result.decision == "cannot_evaluate":
            result = _resolve_cannot_evaluate("Write", path, result, event)
        else:
            try:
                cfg, audit_log = _get_config_and_log()
                _record_normal(audit_log, "Write", path, result, params)
            except Exception:  # noqa: BLE001 — audit failure must not break the hook
                pass

    # Defense in depth: decide() must always return a terminal decision. If a
    # bug ever leaks a non-terminal value, coerce to deny rather than letting
    # format_response treat it as allow.
    if result.decision not in ("allow", "ask", "deny"):
        return GuardResult(decision="deny", reason="Guard internal error")
    return result


def format_response(result: GuardResult) -> dict:
    if result.decision == "deny":
        return {"block": True, "blockReason": result.reason}
    if result.decision == "ask":
        return {
            "requireApproval": {
                "title": "agent-shield",
                "description": result.reason,
                "severity": "warning",
                "allowedDecisions": ["allow-once", "deny"],
            }
        }
    return {}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the TS companion plugin. Reads a before_tool_call event
    JSON on stdin; writes a BeforeToolCallResult JSON to stdout. Always exit 0;
    unparseable input fails open ({} == allow) and oversize input asks, matching
    the Claude Code guards' stdin handling for cross-CLI parity."""
    _ = argv
    try:
        stream = getattr(sys.stdin, "buffer", None)
        if stream is not None:
            raw = stream.read(bash_guard._MAX_READ_BYTES + 1)
            oversize = len(raw) > bash_guard._MAX_READ_BYTES
            stdin_text = bash_guard._decode_stdin_bytes(raw)
        else:
            stdin_text = sys.stdin.read(bash_guard._MAX_READ_BYTES + 1)
            oversize = len(stdin_text) > bash_guard._MAX_READ_BYTES
        if oversize:
            result = GuardResult(decision="ask", reason="Hook input exceeds the size cap — confirm manually")
        else:
            event = json.loads(stdin_text)
            result = decide(event if isinstance(event, dict) else {})
        sys.stdout.write(json.dumps(format_response(result)))
    except Exception:  # noqa: BLE001 — guard contract: never crash
        sys.stdout.write("{}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
