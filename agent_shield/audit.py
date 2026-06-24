"""agent-shield Layer 6 — Structured Audit.

Append-only, tamper-evident JSON-Lines audit log: a 9-field base schema, plus
(added under test) SHA-256 content hashes for write events and a per-entry hash
chain that verify() validates. Stdlib-only; fail-open by default — a logging
failure never raises into the guarded operation.

Tamper-EVIDENT, not tamper-proof: the chain detects edits/inserts/deletes/
reorders, but an attacker with write access can recompute the whole chain from
genesis. Anchor the head externally for tamper-RESISTANCE (see docs/AUDIT_SCHEMA.md).

License: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_FIELDS = ("ts", "actor", "role", "session", "machine",
               "action", "target", "outcome", "details")

#: prev_hash of the first (genesis) entry.
GENESIS = "0" * 64

#: Compliance presets bundle field policy + retention horizon + default fail mode.
#: "general" is the zero-friction default; "healthcare"/"biotech" raise the bar
#: ("no action without an audit record" via fail-closed, uniform 11-field rows,
#: longer retention). Rotation/retention enforcement is documented-not-built in
#: v0.1 (see docs/AUDIT_SCHEMA.md); retention_days is exposed for a Layer-0 cron.
PRESETS = {
    "general":    {"content_fields_always": False, "retention_days": 90,  "fail_mode": "open",   "sanitize_strict": False},
    "healthcare": {"content_fields_always": True,  "retention_days": 365, "fail_mode": "closed", "sanitize_strict": True},
    "biotech":    {"content_fields_always": True,  "retention_days": 365, "fail_mode": "closed", "sanitize_strict": True},
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj: Any) -> str:
    """Deterministic, language-neutral serialization for stable hashing.

    ``allow_nan=False``: a non-finite float in
    ``details`` makes ``json.dumps`` raise ``ValueError`` rather than emit a bare
    ``NaN``/``Infinity`` token — which is invalid JSON and would break every
    parser of the log. The raise is caught by ``_append`` (fail-open drops the
    entry with a warning; fail-closed raises ``AuditWriteError``), so the log
    only ever contains parseable JSON Lines.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _hash_entry(entry_without_hash: dict) -> str:
    """SHA-256 over the canonical entry (excluding entry_hash itself)."""
    return hashlib.sha256(_canonical(entry_without_hash).encode("utf-8")).hexdigest()


def _sha256_hex(data: bytes | str | None) -> str | None:
    """Hex SHA-256 of bytes/str content, or None when no content is supplied."""
    if data is None:
        return None
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    """Result of an audit-chain integrity check."""

    ok: bool
    count: int
    broken_at: int | None = None
    reason: str = ""


@dataclass(frozen=True)
class AnchorHead:
    """The chain tip at anchor time — the ONLY object handed to a shipper.

    A strict non-secret subset of a main-log row (digest + ordinal + timestamp):
    it leaks no actor/role/session/target/details/content, even to an off-box
    bring-your-own shipper.
    """

    seq: int
    entry_hash: str   # the entry's OWN stored entry_hash (the chain tip) — never re-hashed
    ts: str           # the entry's own ts (UTC ISO-8601) — never re-clocked


Shipper = Callable[[AnchorHead], None]
#: A user-supplied sink that receives the chain head and persists/transmits it.
#: agent-shield ships NO network transport ("never phones home"): supply your own
#: Shipper to anchor off-box. A Shipper should not raise — but _maybe_anchor
#: defends against it anyway (a broken shipper never breaks the audited operation).


@dataclass(frozen=True)
class Anchor:
    """Cadence policy + sink for externally anchoring the audit-chain head.

    OFF unless attached to an AuditLog. Stdlib-only, NO network: the built-in
    shipper appends the head to a local JSONL file. Remote anchoring is achieved
    ONLY by supplying your own ``shipper`` callable — agent-shield ships no
    URL/HTTP transport.

    Cadence: anchor when EITHER ``every_n`` entries have been written since the
    last successful anchor, OR ``every_minutes`` have elapsed — whichever first.
    ``every_n=0`` disables the count trigger; ``every_minutes=0`` disables time.
    """

    local_path: Path | None = None
    every_n: int = 100
    every_minutes: float = 15.0
    shipper: Shipper | None = None
    clock: Callable[[], float] | None = None   # default time.monotonic; injected in tests

    def __post_init__(self) -> None:
        if self.every_n < 0:
            raise ValueError(f"every_n must be >= 0, got {self.every_n}")
        if self.every_minutes < 0:
            raise ValueError(f"every_minutes must be >= 0, got {self.every_minutes}")
        if (self.local_path is not None or self.shipper is not None) and self.every_n == 0 and self.every_minutes == 0:
            raise ValueError(
                "Anchor has a sink (local_path or shipper) but both cadence triggers "
                "are disabled (every_n=0 and every_minutes=0); anchoring would be silently off"
            )
        if self.local_path is not None and not isinstance(self.local_path, Path):
            object.__setattr__(self, "local_path", Path(self.local_path))  # frozen-normalize


def _default_local_shipper(local_path: Path) -> Shipper:
    """Filesystem-only shipper: append the head (+ a wall-clock receipt) as JSONL.

    Opened in append mode (never truncate) so a rollback of the main log to an
    older head stays detectable against the anchor's recorded history. Tamper-
    RESISTANCE holds only when local_path is on a target INDEPENDENT of the main
    log (separate volume / write-once dir / another host); on the same writable
    volume it is still only tamper-EVIDENT (see docs/AUDIT_SCHEMA.md).
    """
    def _ship(head: AnchorHead) -> None:
        rec = {"seq": head.seq, "entry_hash": head.entry_hash, "ts": head.ts,
               "anchored_at": _utc_now_iso()}
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "a", encoding="utf-8") as f:
            f.write(_canonical(rec) + "\n")
    return _ship


class AuditWriteError(RuntimeError):
    """Raised by record()/record_write() in fail-closed mode when a write fails.

    In the default fail-open mode no exception ever propagates — the failure is
    reported to stderr and signalled by a None return — so a logging failure can
    never break the operation being audited.
    """


class AuditLog:
    """Append-only, hash-chained audit log writer + verifier.

    preset:
      "general" (default) — 9-field rows, 90-day retention, fail-open.
      "healthcare"/"biotech" — uniform 11-field rows (content-hash slots always
                present, null when N/A), 365-day retention, fail-closed.
    fail_mode (optional; overrides the preset's default):
      "open"   — a write failure is swallowed (stderr warning + None return);
                the guarded operation is never blocked by the audit log.
      "closed" — a write failure raises AuditWriteError, so a caller that
                requires "no action without an audit record" can block the action.
    retention_days is exposed for downstream rotation (documented-not-built in v0.1).
    """

    def __init__(
        self,
        path: str | Path,
        *,
        preset: str = "general",
        fail_mode: str | None = None,
        anchor: Anchor | None = None,
    ) -> None:
        if preset not in PRESETS:
            raise ValueError(f"preset must be one of {sorted(PRESETS)}, got {preset!r}")
        cfg = PRESETS[preset]
        resolved_fail_mode = fail_mode if fail_mode is not None else cfg["fail_mode"]
        if resolved_fail_mode not in ("open", "closed"):
            raise ValueError(
                f"fail_mode must be 'open' or 'closed', got {resolved_fail_mode!r}")
        self.path = Path(path)
        self.preset = preset
        self.fail_mode = resolved_fail_mode
        self.retention_days = cfg["retention_days"]
        self._content_fields_always = cfg["content_fields_always"]
        self._cached_last_entry: dict | None = None   # single-writer tail cache (avoids O(n) re-read)
        self._last_size: int | None = None            # file size after our last write (cache validity)
        # --- Tier-1 anchor wiring (cadence STATE lives on the log, not the frozen Anchor,
        #     so one shared Anchor gives each log its own independent baseline) ---
        self.anchor = anchor
        self.anchor_gap = False                  # public-by-convention: last anchor attempt failed
        self._last_anchored_seq = 0              # genesis baseline (matches GENESIS seq region)
        self._anchor_last_t: float | None = None  # clock() at last successful anchor; None = never
        self._anchor_noop_warned = False
        self._in_anchor_marker = False           # re-entrancy guard for the gap-marker write
        self._anchor_shipper: Shipper | None = None
        self._anchor_clock: Callable[[], float] = time.monotonic
        if anchor is not None:
            self._anchor_clock = anchor.clock or time.monotonic
            if anchor.shipper is not None:
                self._anchor_shipper = anchor.shipper          # BYO shipper wins over local_path
            elif anchor.local_path is not None:
                self._anchor_shipper = _default_local_shipper(anchor.local_path)
            # else: neither set -> _maybe_anchor warns once + no-ops (never an error, never network)

    # ------------------------------------------------------------- internals
    def _last_entry(self) -> dict | None:
        """Return the last VALID entry, or None for a missing/empty log.

        Uses an in-memory cache of this writer's last appended entry (single-writer
        assumption) so repeated appends don't re-scan the whole file — O(1) instead
        of O(n) per write. On a cold read (new instance / re-open) it scans and, if
        the tail line is a torn/partial fragment from a crash, skips BACKWARD to the
        last parseable entry rather than treating the log as empty — so a torn tail
        never silently resets the chain to genesis (see docs/AUDIT_SCHEMA.md).
        """
        if self._cached_last_entry is not None and self._cache_is_fresh():
            return self._cached_last_entry
        if not self.path.exists():
            return None
        lines = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    lines.append(line)
        for line in reversed(lines):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue   # torn/partial fragment — keep scanning back to the last good entry
        return None

    def _cache_is_fresh(self) -> bool:
        """True only if the file still exists and is exactly the size our last successful
        write left it. Detects external rotation / truncation / deletion of a live writer's
        file (and torn partial writes that change the size), so a stale in-memory cache can
        never fabricate a high seq onto a rotated/empty file (which an auditor would read as a
        false TAMPER). On any mismatch we fall through to a fresh disk scan."""
        try:
            return self.path.exists() and self.path.stat().st_size == self._last_size
        except OSError:
            return False

    def _newline_prefix(self) -> str:
        r"""'\n' if the log exists and its last byte is not a newline, else ''.

        O(1) last-byte probe; guards against welding a new entry onto a torn /
        non-newline-terminated final line (which would make verify() see one
        unparseable row where the chain math is actually intact).
        """
        try:
            if self.path.exists():
                size = self.path.stat().st_size
                if size:
                    with open(self.path, "rb") as f:
                        f.seek(-1, os.SEEK_END)
                        if f.read(1) != b"\n":
                            return "\n"
        except OSError:
            pass
        return ""

    def _base_fields(
        self,
        *,
        action: str,
        target: str,
        outcome: str,
        actor: str | None,
        role: str | None,
        session: str | None,
        details: dict | None,
    ) -> dict:
        """The 9 base fields: auto-sourced ts/machine, env-fallback context, safe defaults."""
        return {
            "ts": _utc_now_iso(),
            "actor": actor or os.environ.get("AGENT_SHIELD_ACTOR", "agent"),
            "role": role or os.environ.get("AGENT_SHIELD_ROLE", "unknown"),
            "session": session or os.environ.get("AGENT_SHIELD_SESSION", ""),
            "machine": os.environ.get("AGENT_SHIELD_MACHINE") or socket.gethostname(),
            "action": action,
            "target": target,
            "outcome": outcome,
            "details": details if details is not None else {},
        }

    def _append(self, fields: dict) -> dict | None:
        """Chain (seq/prev_hash/entry_hash) + append one entry as JSON Lines.

        Returns the written entry, or — in fail-open mode — None if any IO or
        serialization step failed (a stderr warning is emitted). In fail-closed
        mode the failure is re-raised as AuditWriteError. By contract this method
        is total in fail-open mode: it never lets an anchor/IO failure reach the
        caller (genuine interrupts like KeyboardInterrupt are intentionally allowed
        to propagate so an operator can still abort).
        """
        try:
            prev = self._last_entry()
            if prev is None:
                seq = 1
                prev_hash = GENESIS
            else:
                seq = int(prev.get("seq", 0)) + 1
                prev_hash = prev.get("entry_hash", GENESIS)

            entry = dict(fields)
            entry["seq"] = seq
            entry["prev_hash"] = prev_hash
            entry["entry_hash"] = _hash_entry(entry)   # serializes — can raise on bad details
            line = _canonical(entry) + "\n"

            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Always O(1)-probe the tail: never weld onto a torn / non-newline-terminated final
            # line. Don't trust the cache to imply a clean '\n' tail — a torn partial write or an
            # external rotation can leave the on-disk tail in another state.
            prefix = self._newline_prefix()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(prefix + line)
            self._cached_last_entry = entry   # single-writer tail cache (avoids O(n) re-read)
            try:
                self._last_size = self.path.stat().st_size   # validates the cache on the next append
            except OSError:
                self._last_size = None
            self._maybe_anchor(entry)   # post-successful-write anchor tick; host-safe, never blocks
            return entry
        except Exception as exc:  # noqa: BLE001 — total by contract; never break the caller
            if self.fail_mode == "closed":
                raise AuditWriteError(str(exc)) from exc
            print(f"agent-shield audit: log write failed (fail-open, not blocking): {exc}",
                  file=sys.stderr)
            return None

    def _maybe_anchor(self, entry: dict) -> None:
        """Anchor the chain head if cadence is due. Host-safe: never lets an anchor
        failure break the audited operation.

        anchor=None => instant no-op => literally zero behavior change. Any anchor
        failure (clock, shipper, IO, serialization) — Exception OR SystemExit — is
        swallowed: the write is already durable, so an anchoring problem must never
        undo or block it, not even in fail-closed mode (fail-closed governs the
        audit-WRITE floor only; the external anchor is best-effort by nature).
        KeyboardInterrupt (and other genuine interrupts) are intentionally NOT
        swallowed, so an operator's Ctrl-C still aborts.
        """
        if self.anchor is None:
            return
        if self._in_anchor_marker:           # a gap-marker write must not recurse
            return
        a = self.anchor
        try:
            seq = int(entry["seq"])
            now = self._anchor_clock()
            due_count = a.every_n > 0 and (seq - self._last_anchored_seq) >= a.every_n
            if self._anchor_last_t is None:
                self._anchor_last_t = now    # seed the time baseline on the first observed tick
                due_time = False
            else:
                due_time = a.every_minutes > 0 and (now - self._anchor_last_t) >= a.every_minutes * 60.0
            if not (due_count or due_time):
                return
            if self._anchor_shipper is None:  # anchor configured with neither shipper nor local_path
                self._warn_anchor_noop_once()
                self._last_anchored_seq = seq
                self._anchor_last_t = now
                return
            head = AnchorHead(seq=seq, entry_hash=str(entry["entry_hash"]), ts=str(entry["ts"]))
        except (Exception, SystemExit):       # host-safe; KeyboardInterrupt still propagates
            return
        # Shipper invocation: catch Exception + SystemExit so a buggy/malicious shipper can't
        # crash or sys.exit() the host — but let KeyboardInterrupt (and other genuine interrupts)
        # propagate so an operator's Ctrl-C still aborts.
        try:
            self._anchor_shipper(head)
        except (Exception, SystemExit) as exc:   # noqa: BLE001 — fail-open; see docs/AUDIT_SCHEMA.md
            first_failure = not self.anchor_gap   # coalesce: one marker + warning per failure streak
            self.anchor_gap = True
            if first_failure:
                print(f"agent-shield audit: anchor failed (not blocking write): {exc!r}",
                      file=sys.stderr)
                self._write_gap_marker(seq, exc)
            return                            # baselines NOT advanced -> retry next cadence
        # success: advance both baselines (whichever-first reset) + clear the gap
        self._last_anchored_seq = seq
        self._anchor_last_t = now
        self.anchor_gap = False

    def _write_gap_marker(self, seq: int, exc: BaseException) -> None:
        """Record a failed-anchor gap as a normal chained entry, so the gap is
        itself tamper-evident. Re-entrancy-guarded so it can never recurse into
        _maybe_anchor (a persistently-failing shipper would otherwise loop)."""
        self._in_anchor_marker = True
        try:
            target = str(getattr(self.anchor, "local_path", None) or "<shipper>")
            self.record(action="audit.anchor", target=target, outcome="error",
                        details={"anchor_seq": seq, "error": type(exc).__name__})
        except (Exception, SystemExit):       # noqa: BLE001 — marker is best-effort; never blocks
            pass
        finally:
            self._in_anchor_marker = False

    def _warn_anchor_noop_once(self) -> None:
        if not self._anchor_noop_warned:
            self._anchor_noop_warned = True
            print("agent-shield audit: anchor configured with no local_path and no shipper — "
                  "anchoring is a no-op (no network is ever used).", file=sys.stderr)

    # ------------------------------------------------------------- public API
    def record(
        self,
        *,
        action: str,
        target: str,
        outcome: str,
        actor: str | None = None,
        role: str | None = None,
        session: str | None = None,
        details: dict | None = None,
    ) -> dict | None:
        """Append one hash-chained audit entry as a JSON-Lines record.

        action/target/outcome are caller-required; ts/machine are auto-sourced;
        actor/role/session fall back to AGENT_SHIELD_* env vars then safe
        defaults; details is caller-controlled. seq/prev_hash/entry_hash form
        the tamper-evident chain. A non-write event under the general preset is
        exactly the 9 base fields (no content hashes).
        """
        fields = self._base_fields(
            action=action, target=target, outcome=outcome,
            actor=actor, role=role, session=session, details=details,
        )
        if self._content_fields_always:
            # healthcare/biotech: uniform 11-field rows — content slots present (null)
            fields["content_sha256_before"] = None
            fields["content_sha256_after"] = None
        return self._append(fields)

    def record_write(
        self,
        *,
        target: str,
        outcome: str,
        content_before: bytes | str | None = None,
        content_after: bytes | str | None = None,
        action: str = "write",
        actor: str | None = None,
        role: str | None = None,
        session: str | None = None,
        details: dict | None = None,
    ) -> dict | None:
        """Append a write event, adding the two SHA-256 content-integrity fields.

        content_before/after may be bytes or str (str is UTF-8 encoded); each is
        hashed to a hex digest, or recorded as null when not supplied (e.g. a
        blocked write that produced no bytes). All other semantics match record().
        """
        fields = self._base_fields(
            action=action, target=target, outcome=outcome,
            actor=actor, role=role, session=session, details=details,
        )
        fields["content_sha256_before"] = _sha256_hex(content_before)
        fields["content_sha256_after"] = _sha256_hex(content_after)
        return self._append(fields)

    def verify(self) -> VerifyResult:
        """Walk the chain, recomputing each entry hash and link.

        Detects edits, insertions, deletions, and reorders: any of them break
        either the recomputed entry_hash, the prev_hash link, or the seq order.
        """
        if not self.path.exists():
            return VerifyResult(ok=True, count=0)

        prev_hash = GENESIS
        expected_seq = 1
        count = 0
        with open(self.path, "r", encoding="utf-8") as f:
            for raw in f:
                if not raw.strip():
                    continue
                count += 1
                try:
                    e = json.loads(raw)
                except json.JSONDecodeError:
                    return VerifyResult(False, count, expected_seq, "unparseable line")
                if e.get("seq") != expected_seq:
                    return VerifyResult(False, count, expected_seq, "seq out of order")
                if e.get("prev_hash") != prev_hash:
                    return VerifyResult(False, count, expected_seq, "broken chain link")
                stored = e.get("entry_hash")
                recomputed = _hash_entry({k: v for k, v in e.items() if k != "entry_hash"})
                if stored != recomputed:
                    return VerifyResult(False, count, expected_seq, "entry hash mismatch")
                prev_hash = stored
                expected_seq += 1
        return VerifyResult(ok=True, count=count)


def main(argv: list[str] | None = None) -> int:
    """CLI: verify an audit log's tamper-evident hash chain.

    `python -m agent_shield.audit --verify <path>`
      exit 0 = chain intact · 1 = tamper detected · 2 = missing / unreadable.
    """
    parser = argparse.ArgumentParser(
        prog="agent_shield.audit",
        description="Verify an agent-shield audit log's tamper-evident hash chain.",
    )
    parser.add_argument(
        "--verify", metavar="PATH", required=True,
        help="path to the audit JSON-Lines log to verify",
    )
    args = parser.parse_args(argv)
    path = Path(args.verify)

    if not path.exists():
        print(f"agent-shield audit: not found: {path}", file=sys.stderr)
        return 2
    try:
        with open(path, "r", encoding="utf-8"):
            pass  # readability probe (also catches is-a-directory)
    except OSError as exc:
        print(f"agent-shield audit: unreadable: {exc}", file=sys.stderr)
        return 2

    result = AuditLog(path).verify()
    if result.ok:
        print(f"OK: chain intact ({result.count} entries)")
        return 0
    print(
        f"TAMPER: {result.reason} at entry {result.broken_at} "
        f"(after reading {result.count} entr{'y' if result.count == 1 else 'ies'})",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
