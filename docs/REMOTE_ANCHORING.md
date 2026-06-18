# Remote anchoring (optional, opt-in)

agent-shield's Layer 6 audit log is **tamper-evident** on its own. Anchoring the
chain head to an **independent** location upgrades it to **tamper-resistant** —
even a full-genesis rewrite of the local log is then detectable. The built-in
anchor writes to a local path; this guide covers the **opt-in** case where you
want to anchor to a **remote** endpoint instead.

> **The trade-off, stated plainly.** agent-shield **never phones home** — the
> shipped package contains no networking code, and a test enforces that. Remote
> anchoring is achieved with a **bring your own shipper**: a small callable *you*
> supply that transmits the head to *your* endpoint. Enabling it means **your
> deployment** now makes an outbound call — you are choosing to opt *your setup*
> out of the no-egress default. agent-shield is not doing it; your shipper is.

## What actually leaves the box

Only the chain **head**: `{seq, entry_hash, ts}` — a SHA-256 digest, a counter,
and a UTC timestamp. **No** actor, role, session, target, command, file content,
or `details` is ever sent. The head is a strict, non-secret subset of a row the
local log already holds, so anchoring leaks nothing the log didn't already record
locally.

## How to enable it — pick your comfort level

**1. You use an AI agent (no coding).** Hand it this guide plus
[`examples/remote_anchor_shipper.py`](../examples/remote_anchor_shipper.py) and say:

> *"Enable remote audit anchoring per `docs/REMOTE_ANCHORING.md`. Send the receipts
> to `https://my-endpoint.example/anchor`. Show me the change before applying it."*

The agent copies the recipe, sets your endpoint, wires it into your `AuditLog`,
and shows you the diff. This reuses agent-shield's standard agent-assisted install
flow (see `INSTALL_AGENT.md`).

**2. You can copy-paste (one line of editing).** Copy
`examples/remote_anchor_shipper.py` into your project and either edit the single
marked `DEFAULT_ANCHOR_URL` line or pass your URL to `make_url_shipper(...)`:

```python
from agent_shield import audit
from remote_anchor_shipper import make_url_shipper

log = audit.AuditLog(
    "audit.jsonl",
    anchor=audit.Anchor(shipper=make_url_shipper("https://my-endpoint.example/anchor")),
)
```

Run `python examples/remote_anchor_shipper.py` for a **dry run** that prints
exactly what would be sent — without sending anything.

**3. You write code.** A shipper is just `Callable[[AnchorHead], None]`. Build your
own (a notary client, a cloud object-lock `put`, an append to a remote WORM store)
and pass it as `audit.Anchor(shipper=your_callable)`. The package's own API has no
`url`/`endpoint` parameter — the transport is entirely yours.

## Risks & how to mitigate them

- **The unanchored tail is still forgeable.** Anchoring is *periodic* — it protects
  entries only up to the last anchored `seq`. Everything written since (a window
  bounded by `every_n` / `every_minutes`) is unprotected: an attacker who preserves
  the anchored prefix and re-chains only the tail passes both `verify()` and the
  anchored-head check. Keep cadences small and anchor on shutdown to shrink the
  window (`every_n=1` closes it). See "Blind spot — the unanchored tail" in
  [`AUDIT_SCHEMA.md`](AUDIT_SCHEMA.md#external-anchoring-tier-1).
- **Choose a genuinely independent target.** Tamper-*resistance* holds only when
  the anchor target is somewhere the attacker who can rewrite your local log
  **cannot** also rewrite: a separate host, an append-only / write-once (WORM)
  store, or a third-party notary. An endpoint on the same box or same admin domain
  is not independent — you stay tamper-evident only.
- **Use TLS and verify it.** `https://` only. The receipt is non-secret, but an
  attacker who can MITM or spoof your endpoint can swallow receipts (hiding a gap)
  or feed you false confirmations. Pin/verify the endpoint's certificate per your
  environment.
- **Treat the endpoint URL as security-sensitive config.** If an attacker can edit
  your agent-shield configuration, they can repoint the anchor at their own server
  (an SSRF-style redirection) and neutralize the resistance. Protect the config
  the same way you protect the guard settings (Layer 4 already guards
  `agent-shield` config writes).
- **Mind enterprise egress policy.** Many regulated environments forbid unexpected
  outbound connections. Remote anchoring is exactly such a connection — clear it
  with your security team, and prefer an internal/allowlisted collector.
- **Keep the shipper fast.** It runs **synchronously, in-process**, and v0.1 has
  no in-process timeout (that needs threads). A slow or hanging endpoint will stall
  the cadence-due audited write for as long as it blocks. Use a short timeout (the
  recipe defaults to 5s) and, if your endpoint can be slow, do the slow work
  asynchronously in your own shipper (e.g. enqueue and return).
- **Failures are safe but visible.** A shipper that *raises* never blocks the write:
  agent-shield flags `log.anchor_gap`, records a tamper-evident `audit.anchor`/
  `error` marker, and retries on the next cadence. Monitor `anchor_gap` (and your
  collector) so a silently-down endpoint doesn't leave you unanchored for long.

## See also

- [`AUDIT_SCHEMA.md`](AUDIT_SCHEMA.md) — the audit schema, the local anchor, and the
  full tamper-evident / tamper-resistant / not-tamper-proof threat model.
- [`examples/remote_anchor_shipper.py`](../examples/remote_anchor_shipper.py) — the
  ready-to-copy recipe this guide refers to.
