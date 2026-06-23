"""_telemetry — agent-shield v0.2 Phase F1/F4.

Audit helpers for the error path. ``record_guard_unavailable`` writes a
structured, sanitized audit record for every ``cannot_evaluate`` resolution.
``observe_visibility_hook`` layers the extra visibility required by the
``observe`` policy: a per-session stderr banner + durable counter.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import json
import os
import re
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any

from agent_shield import audit
from agent_shield._error_policy import OUTCOME_REASONS

#: Max characters of the raw command/path we write to the audit ``target`` field.
_TARGET_MAX_LEN = 4096

#: Credential-like tokens we redact from the target before logging.
#: Matches env-style assignments (`TOKEN=...`) and HTTP-style bearer/header
#: secrets (`Authorization: Bearer ...`, `X-Api-Key: ...`, `token=...`).
#: Values may be quoted (`"..."`, `'...'`) or unquoted; unquoted values run to
#: the next semicolon/quote, which safely includes embedded spaces and newlines
#: while keeping command separators intact. Quoted strings honor backslash-escaped
#: quotes so that an escaped `"` does not prematurely end the redacted span.
_SECRET_VALUE_RE = r'(?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^;\"\']+)'
_SECRET_REDACT_RE = re.compile(
    r"(?:"
    r"\b[A-Z_]*(?:TOKEN|KEY|SECRET|PASSWORD|CRED)[A-Z_]*\s*[:=]\s*" + _SECRET_VALUE_RE
    + r"|"
    r"[A-Za-z_-]*(?:Authorization|Api-Key|Token|Secret|Key)\s*[:=]\s*(?:Bearer\s+)?" + _SECRET_VALUE_RE
    + r")",
    re.IGNORECASE,
)

#: One-line stderr banner for the first would-have-blocked per session.
_OBSERVE_BANNER = (
    "agent-shield: a command was allowed but would have been blocked "
    "under error_policy=observe; see the audit log for details."
)

#: Default path for the per-session observe counter.
_DEFAULT_OBSERVE_COUNTER_PATH = Path("~/.agent-shield/observe-counter.json")

#: GC stale entries older than this many seconds.
_OBSERVE_COUNTER_TTL_SECONDS = 24 * 60 * 60


def _decision_from_reason(outcome_reason: str) -> str:
    """Map a resolver outcome_reason to the terminal decision written to audit."""
    if outcome_reason in ("allowed-selfrepair", "allowed-unevaluated", "would-have-blocked"):
        return "allow"
    if outcome_reason == "asked-unevaluated":
        return "ask"
    return "deny"


def sanitize_target(raw: str) -> str:
    """Prepare a raw command/path for the audit ``target`` field.

    - Redacts obvious credential-like tokens (``TOKEN=...``, ``PASSWORD=...``).
    - Caps length at :data:`_TARGET_MAX_LEN`; longer inputs are truncated and
      suffixed with ``...``.
    """
    try:
        if not isinstance(raw, str):
            raw = str(raw)
        redacted = _SECRET_REDACT_RE.sub("<redacted>", raw)
        if len(redacted) > _TARGET_MAX_LEN:
            return redacted[: _TARGET_MAX_LEN - 3] + "..."
        return redacted
    except Exception:  # noqa: BLE001 — never let sanitization break the caller
        return "<sanitization-error>"


def record_guard_unavailable(
    audit_log: audit.AuditLog,
    raw: str,
    trigger: str,
    action_tier: str | None,
    attended: bool,
    error_policy: str,
    outcome_reason: str,
    harness: str | None,
) -> dict | None:
    """Record one ``guard_unavailable`` audit row for a resolved error-path event.

    ``outcome`` is the terminal decision (allow/ask/deny). ``outcome_reason`` is
    stored in ``details``. ``target`` is sanitized before logging.

    Returns the audit entry dict, or None if the audit log is fail-open and the
    write failed.
    """
    if outcome_reason not in OUTCOME_REASONS:
        outcome_reason = "denied-unevaluated"
    outcome = _decision_from_reason(outcome_reason)
    details: dict[str, Any] = {
        "trigger": trigger,
        "action_tier": action_tier if action_tier is not None else "unknown",
        "attended": attended,
        "outcome_reason": outcome_reason,
        "guard_authoritative": False,
        "error_policy": error_policy,
        "harness": harness,
    }
    return audit_log.record(
        action="guard_unavailable",
        target=sanitize_target(raw),
        outcome=outcome,
        details=details,
    )


# ---------------------------------------------------------------------------
# F4 — observe visibility
# ---------------------------------------------------------------------------
_observe_banner_sessions: set[str] = set()  # sessions that have already seen the banner
_observe_warned = False  # one-time warning if the counter file is unwritable


def _session_key(session: str | None) -> str:
    """Return a stable session identifier for the observe counter."""
    if session:
        return session
    try:
        machine = socket.gethostname()
    except Exception:  # noqa: BLE001
        machine = "unknown"
    return f"{machine}-{os.getpid()}"


def _load_counter(path: Path) -> dict[str, Any]:
    """Load the observe counter JSON, GCing entries older than 24h."""
    now = _monotonic_now_seconds()
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001 — corrupted/empty/missing file is not fatal
        return {}
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    for key, entry in data.items():
        if not isinstance(entry, dict):
            continue
        last_seen = entry.get("last_seen_ts", 0)
        if now - last_seen < _OBSERVE_COUNTER_TTL_SECONDS:
            cleaned[key] = entry
    return cleaned


def _atomic_write_json(path: Path, data: dict) -> None:
    """Write JSON atomically using temp-file + rename (Windows-safe)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _monotonic_now_seconds() -> int:
    """Seconds since epoch; used for TTL/GC."""
    import time

    return int(time.time())


def observe_visibility_hook(
    audit_log: audit.AuditLog,
    raw: str,
    trigger: str,
    action_tier: str | None,
    attended: bool,
    error_policy: str,
    harness: str | None,
    session: str | None = None,
    counter_path: Path | None = None,
) -> dict | None:
    """Record a ``would-have-blocked`` observe event with extra visibility.

    Writes the audit record via :func:`record_guard_unavailable`, then:
      - increments a per-session counter in a JSON file,
      - prints a one-time stderr banner on the first would-have-blocked in this
        process/session.

    If ``counter_path`` is unwritable, emits a one-time stderr warning and
    continues; the audit record is still written.
    """
    global _observe_warned

    entry = record_guard_unavailable(
        audit_log=audit_log,
        raw=raw,
        trigger=trigger,
        action_tier=action_tier,
        attended=attended,
        error_policy=error_policy,
        outcome_reason="would-have-blocked",
        harness=harness,
    )

    path = (counter_path or _DEFAULT_OBSERVE_COUNTER_PATH).expanduser()
    key = _session_key(session)

    try:
        counter = _load_counter(path)
        rec = counter.get(key, {"count": 0, "first_seen_ts": 0, "last_seen_ts": 0})
        now = _monotonic_now_seconds()
        rec["count"] = int(rec.get("count", 0)) + 1
        rec["last_seen_ts"] = now
        if rec.get("first_seen_ts", 0) == 0:
            rec["first_seen_ts"] = now
        counter[key] = rec
        _atomic_write_json(path, counter)

        if key not in _observe_banner_sessions and rec["count"] == 1:
            _observe_banner_sessions.add(key)
            print(_OBSERVE_BANNER, file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — counter is best-effort
        if not _observe_warned:
            _observe_warned = True
            print(
                f"agent-shield: observe counter unavailable ({exc}); "
                "audit record still written.",
                file=sys.stderr,
            )

    return entry
