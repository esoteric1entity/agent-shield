"""Opt-in remote anchor shipper for agent-shield's Layer 6 audit log.

=============================================================================
  READ THIS FIRST — you are turning on outbound network traffic, on purpose.
=============================================================================
agent-shield itself ships **no networking code** — it "never phones home."
This file is an OPTIONAL recipe you copy into *your own* project. By wiring it
in, **your deployment** starts sending a tiny integrity receipt to an endpoint
**you** choose. That is a deliberate, informed trade-off: you gain stronger,
off-box tamper-RESISTANCE, and in exchange your audit pipeline now makes an
outbound call. agent-shield is not doing it — *your* shipper is.

Only the chain **head** is sent — `{seq, entry_hash, ts}` — a SHA-256 digest, a
counter, and a timestamp. No actor, target, command, file content, or `details`
ever leaves the box. Read `docs/REMOTE_ANCHORING.md` for the risks (independent
target, TLS, endpoint trust, SSRF, enterprise egress policy) before deploying.

Stdlib only (`json`, `urllib`); Python >= 3.12. Apache-2.0.

---------------------------------------------------------------------------
Usage (developer):

    from agent_shield import audit
    from remote_anchor_shipper import make_url_shipper

    log = audit.AuditLog(
        "audit.jsonl",
        anchor=audit.Anchor(shipper=make_url_shipper("https://your-notary.example/anchor")),
    )

Usage (non-coder): hand this file + docs/REMOTE_ANCHORING.md to your agent and
say: "enable remote audit anchoring per the guide; send to <my endpoint>."
---------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import urllib.request

# ==>  THE ONE LINE TO EDIT  <==============================================
#  Set this to YOUR collector endpoint (use https:// — see the risk guide),
#  or pass it to make_url_shipper(...) directly and leave this as-is.
DEFAULT_ANCHOR_URL = "https://CHANGE-ME.example/anchor"
# =========================================================================


def build_anchor_request(url: str, head) -> urllib.request.Request:
    """Build (but do NOT send) the POST request for one anchor head.

    Pure function — no I/O — so it is easy to unit-test. `head` is the object
    agent-shield hands a shipper: it exposes `.seq`, `.entry_hash`, `.ts`.
    """
    payload = json.dumps(
        {"seq": head.seq, "entry_hash": head.entry_hash, "ts": head.ts}
    ).encode("utf-8")
    return urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "agent-shield-anchor/0.1",
        },
    )


def make_url_shipper(url: str = DEFAULT_ANCHOR_URL, *, timeout: float = 5.0):
    """Return a shipper callable that POSTs each anchor head to `url`.

    Wire the result into `audit.Anchor(shipper=...)`. The shipper lets network
    errors raise: agent-shield catches them, flags `log.anchor_gap`, writes a
    tamper-evident gap marker, and retries on the next cadence — your audited
    operation is never blocked. Keep `timeout` small: the shipper runs
    **synchronously, in-process**, so a slow endpoint slows the cadence-due write.
    """
    def _ship(head) -> None:
        req = build_anchor_request(url, head)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — user-chosen URL
            resp.read()  # drain + confirm the request completed
    return _ship


if __name__ == "__main__":
    # Dry run: show exactly what WOULD be sent — makes no network call.
    import types

    sample = types.SimpleNamespace(seq=42, entry_hash="0" * 64, ts="1970-01-01T00:00:00Z")
    request = build_anchor_request(DEFAULT_ANCHOR_URL, sample)
    print(f"POST {request.full_url}")
    print(f"headers: {dict(request.header_items())}")
    print(f"body:    {request.data.decode('utf-8')}")
    print("\n(dry run — nothing was sent. Set DEFAULT_ANCHOR_URL and wire make_url_shipper "
          "into audit.Anchor(shipper=...) to enable. See docs/REMOTE_ANCHORING.md.)")
