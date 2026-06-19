# Audit log schema & integrity model (Layer 6)

`agent-shield`'s Layer 6 is a **structured, append-only, tamper-evident** forensic
log: one JSON object per line (JSON Lines), each entry hash-chained to the one
before it. It is **evidence, not a protection layer** — it records what happened
so an after-the-fact edit, insertion, deletion, or reorder is *detectable*.

Stdlib-only. **Zero runtime dependencies, and it never phones home** (see
[External anchoring](#external-anchoring-tier-1) for the one place data can leave
the box — and why that is entirely under your control).

---

## Schema

Every row is one JSON object. Fields:

### Base (9) — present on every entry

| Field | Type | Source |
|---|---|---|
| `ts` | string (UTC ISO-8601) | auto — time of the record |
| `actor` | string | caller arg → `AGENT_SHIELD_ACTOR` env → `"agent"` |
| `role` | string | caller arg → `AGENT_SHIELD_ROLE` env → `"unknown"` |
| `session` | string | caller arg → `AGENT_SHIELD_SESSION` env → `""` |
| `machine` | string | `AGENT_SHIELD_MACHINE` env → `socket.gethostname()` |
| `action` | string | **caller-required** |
| `target` | string | **caller-required** |
| `outcome` | string | **caller-required** |
| `details` | object | caller-controlled (default `{}`) |

No PII is collected by default; `details` is whatever the caller passes.

### Write-event extension (2) — content integrity

`record_write(...)` adds two fields (hex SHA-256 of the bytes, or `null` when not
supplied — e.g. a blocked write that produced no bytes):

| Field | Type |
|---|---|
| `content_sha256_before` | string\|null |
| `content_sha256_after` | string\|null |

Under the **general** preset these appear only on write events; under
**healthcare/biotech** they are present on every row (null when N/A) so all rows
share a uniform 11-field shape.

### Chain (3) — tamper-evidence

| Field | Type | Meaning |
|---|---|---|
| `seq` | int | monotonic ordinal (starts at 1) |
| `prev_hash` | string | the prior entry's `entry_hash` (genesis = 64 zeros) |
| `entry_hash` | string | `sha256(canonical(entry-without-entry_hash))` |

---

## Canonical serialization

Hashing uses a deterministic, language-neutral form so the same logical entry
hashes identically across runs and platforms:

```python
json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
```

`allow_nan=False` makes a non-finite float in a write event's `details` raise
rather than emit bare `NaN` / `Infinity` (which is not valid JSON and would
break cross-implementation verification).

`entry_hash` is computed over the entry with every field **except** `entry_hash`
itself; the result is then stored as `entry_hash`. A verifier recomputes the same
value and compares.

---

## Verification

**Library:**

```python
from agent_shield import audit
log = audit.AuditLog("audit.jsonl")
report = log.verify()      # VerifyResult(ok, count, broken_at, reason)
```

`verify()` walks the chain and returns `ok=False` (with `broken_at` and a
`reason`) on the first detected edit, insertion, deletion, reorder, or
unparseable line.

**CLI:**

```bash
python -m agent_shield.audit --verify audit.jsonl
#   exit 0 = chain intact   ·   1 = tamper detected   ·   2 = missing / unreadable
```

---

## Compliance presets

| Preset | Row shape | Retention | Default write-fail mode |
|---|---|---|---|
| `general` (default) | 9 fields (writes carry 11) | 90 days | **fail-open** |
| `healthcare` / `biotech` | uniform 11 fields | 365 days | **fail-closed** |

- **fail-open** (general): a failed audit write is swallowed — it prints a stderr
  warning and returns `None`, but **never blocks the operation being audited**.
- **fail-closed** (healthcare/biotech): a failed audit write raises
  `AuditWriteError`, so a caller that requires "no action without an audit record"
  can block the operation. Set it explicitly with `AuditLog(path, fail_mode="closed")`.

`retention_days` is exposed for a downstream rotation job; **rotation/retention
enforcement is documented-not-built in v0.1** (a Layer-0 cron concern).

---

## External anchoring (Tier-1)

A purely-local hash chain is **tamper-evident** but not tamper-resistant: an
attacker with write access can rewrite the whole file from genesis into a fresh,
internally-valid chain. The defence is to copy the chain **head** — a minimal
receipt `{seq, entry_hash, ts}` — somewhere the attacker cannot reach. Then a
later rewrite no longer matches the anchored heads, and the divergence is
detectable.

```python
from pathlib import Path
from agent_shield import audit

log = audit.AuditLog(
    "audit.jsonl",
    anchor=audit.Anchor(local_path=Path("/mnt/worm/anchor.jsonl")),  # an INDEPENDENT target
)
```

- **Cadence:** anchors when **either** `every_n` entries (default 100) **or**
  `every_minutes` (default 15) have passed since the last successful anchor —
  whichever first. It is **never per-event** at the defaults (per-event would add
  latency to every guarded action). `every_n=0` disables the count trigger;
  `every_minutes=0` disables the time trigger. (Setting `every_n=1` makes anchoring
  per-event — supported, but it forfeits the never-per-event property, and with a
  persistently-failing shipper it re-attempts on every record.) After missed
  anchors, the **latest** head at fire time is shipped — not each individually-missed
  head.
- **Fail-open — a *failing* anchor never blocks the write:** a shipper that raises
  (including `SystemExit`) is caught, **never** propagated into the audited operation
  — not even under the fail-closed preset. The failure sets the `log.anchor_gap`
  flag, prints one stderr warning, and writes a chained `action="audit.anchor"`,
  `outcome="error"` marker into the main log (so the gap is itself tamper-evident),
  coalesced to **one marker per failure-streak**. The cadence baseline is **not**
  advanced on failure, so the next entry re-attempts. A `KeyboardInterrupt` is
  intentionally **not** swallowed, so an operator's Ctrl-C still aborts. The shipper
  runs **synchronously, in-process** (see the caveat below): a *failing* shipper
  never blocks, but a *slow/hanging* one will.
- **The head carries only `{seq, entry_hash, ts}`** — no `actor`/`role`/`session`/
  `target`/`details`/content. It is a strict non-secret subset of a row the main
  log already holds.
- **Blind spot — the unanchored tail.** Anchoring protects only entries up to the
  **most-recently anchored** `seq`. Everything written **since** the last
  successful anchor (a window bounded by `every_n` / `every_minutes`) is not yet
  anchored, so an attacker with write access who **preserves the anchored prefix**
  and re-chains only that tail produces a log that still passes local `verify()`
  **and** matches every anchored head — the forgery in the tail is undetectable
  until the next anchor fires. This is an inherent property of *periodic*
  anchoring, not a bug. Mitigation: use **small cadences** (low `every_n` /
  `every_minutes`) and **anchor on shutdown** so the unprotected window stays
  short; `every_n=1` closes it entirely at the cost of the never-per-event
  property. `verify()` alone only proves internal chain consistency — it cannot
  detect a from-genesis (or from-last-anchor) rewrite; that is precisely what the
  external anchor is for.

### never phones home

**agent-shield makes no outbound network calls.** Its only socket use is a local `gethostname()` for the audit record; the built-in anchor shipper writes only to a local filesystem path. To anchor off-box (a remote notary, an append-only object
store, another host), you **bring your own shipper** — a callable that receives the
head and transmits it however *you* choose:

```python
def my_shipper(head):                 # YOUR code, YOUR egress, YOUR policy
    ...                               # e.g. POST head.entry_hash to your notary

log = audit.AuditLog("audit.jsonl", anchor=audit.Anchor(shipper=my_shipper))
```

There is no `url`/`endpoint`/`webhook` parameter anywhere in the API, and the
shipped package makes **no outbound network calls** — it imports `socket` solely
for `socket.gethostname()` (to stamp the `machine` field) and never opens a
connection. This is checked by a **best-effort AST lint** in the test suite (not a
sandbox): it flags networking-client imports (e.g. `urllib`, `http.client`,
`requests`), `socket`-connect-family calls (alias- and from-import-aware), and
`subprocess`/`os.system`/`eval`-family egress (the stdlib `socket` import, used
only for `gethostname()`, is permitted). A static lint raises the cost of an
accidental regression; it is not a guarantee against a determined maintainer. The
one piece of network *capability* in the system is the shipper **you** supply. For a
ready-to-copy `urllib` shipper recipe and the full opt-in risk guide (independent
target, TLS, endpoint trust, egress policy, keep-it-fast), see
[`REMOTE_ANCHORING.md`](REMOTE_ANCHORING.md).

> A shipper runs synchronously, in-process, inside a fault barrier: a shipper that
> raises (including `SystemExit`) is caught and flagged, never propagated — but a
> `KeyboardInterrupt` IS allowed through, so Ctrl-C still works. A shipper that
> **blocks/hangs** cannot be timed out in-process in v0.1 (that needs threads) —
> keep your shipper fast, or do its slow work asynchronously yourself.

---

## Threat model & honest limits

- **Tamper-EVIDENT — always.** The chain detects edits, insertions, deletions, and
  reorders of the local log.
- **Not tamper-proof — ever.** Anything the verifier can recompute, an attacker
  with local write access can also recompute. A self-verifying local log can be
  rewritten wholesale from genesis and will still `verify()` clean.
- **Tamper-RESISTANT — only when anchored to a truly independent target.** The
  anchor delivers real resistance *only* if its target is outside the attacker's
  reach: a separate **independent** volume, a write-once/WORM location, or another
  host. **An anchor file on the same writable volume as the main log is not
  independent** — the same attacker rewrites both, so you are back to
  tamper-evident only. Choose the anchor target accordingly.
- **Never "tamper-proof."** We do not use that word.

## Bypasses & limitations

- **Full-genesis rewrite is invisible to `verify()` alone** — that is the precise
  gap the external anchor closes (and only when the anchor target is independent).
- **Single-writer assumption.** Appends + chaining assume one writer; an OS-level
  file lock is documented-not-built for v0.1. Concurrent writers can interleave and
  break the chain — run one writer per log, or add your own lock. (The last-entry
  tail read is cached in-memory per writer so appends stay O(1) rather than
  re-scanning the file; the cache is **validated against the file's size on every
  append**, so an external rotation / truncation / deletion of a live writer's file
  is detected and the chain restarts cleanly — a stale seq is never mis-chained onto
  a rotated or emptied file.)
- **Crash mid-append.** A torn/partial final line (power loss, disk-full, or a tool
  that drops the final newline) is handled safely: the next write skips back to the
  last valid entry and continues the chain — no genesis reset, no duplicate `seq` —
  and starts on its own line (never welded onto the fragment). `verify()` still
  reports the torn fragment as an `unparseable line` (honest: the corruption is
  real), so recovery means excising that one line; the chain on either side stays
  sound.
- **Rotation/retention is exposed-not-enforced** in v0.1 (`retention_days` is a
  hint for a Layer-0 cron; seal-and-archive rotation is a future addition).
- **A logging failure is not an audited-operation failure** (general preset) — by
  design. If your threat model needs the inverse, use `fail_mode="closed"`.

For *guarantees* against a determined adversary you still need OS-level controls
(append-only storage, an independent notary, least-privilege users) underneath this
layer. The audit log is forensic evidence, not a cage.
