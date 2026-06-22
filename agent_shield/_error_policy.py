"""_error_policy — the error-path resolver (agent-shield v0.2, neutral core).

The single place that turns a "the guard could not evaluate this action"
situation (a ``cannot_evaluate``) into a TERMINAL decision (``allow`` / ``ask``
/ ``deny``). It is PURE logic: it imports NEITHER the guards NOR the allowlist
— both the catastrophic-RED check and the never-self-lockout check are RECEIVED
as callables (so there is no import cycle; the C1/D1 adapters wire them).

Resolution order (LOCKED — all checks live INSIDE this function, in this order):

  1. Self-lockout (highest precedence; the ONLY path that skips the RED check):
     if the self-lockout checker is wired and returns True -> ``allow``
     (self-repair commands must never lock the operator out of their own box).
  2. Catastrophic-RED override (beats policy): if the RED check is wired and its
     first tuple element is True -> ``deny`` (a known-catastrophic action is
     denied even under ``error_policy="open"``).
  3. Policy tier (``open`` / ``closed`` / ``ask`` / ``observe``), modulated by
     ``attended`` for the ``ask`` tier.

``trigger`` is METADATA ONLY — the decision MUST be invariant across trigger
values; the resolver never branches on it (it is carried into the later audit
record built by the adapter).

Defense-in-depth guarantees (this resolver is the security chokepoint):
  - **Never propagates a callable's exception.** Each callable is invoked inside
    a guard; a raising callable is treated as its safe-direction False (RED ->
    not-RED, i.e. no downgrade; self-lockout -> not-on-allowlist, i.e. no
    allow-exception) and resolution continues.
  - **Never returns ``cannot_evaluate``.** Every code path returns a terminal
    allow/ask/deny.
  - **Fails CLOSED on an unrecognized policy** — an unknown ``error_policy``
    resolves to ``deny`` (a security resolver must never fall through to allow).

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

#: The terminal policy tiers ``error_policy`` may take.
KNOWN_POLICIES: Final = frozenset({"open", "closed", "ask", "observe"})

#: The seven exact ``outcome_reason`` strings this resolver can return.
#: (Single-sourced here so the audit layer and tests can reference one table.)
OUTCOME_REASONS: Final = frozenset(
    {
        "allowed-selfrepair",
        "denied-catastrophic-unevaluated",
        "allowed-unevaluated",
        "denied-unevaluated",
        "asked-unevaluated",
        "would-have-asked",
        "would-have-blocked",
    }
)


def _safe_red(red_check_callable: Callable[[str], tuple[bool, str]], raw: str) -> bool:
    """Invoke the RED check, returning its first tuple element as a plain bool.

    ``red_check_callable(raw)`` follows the ``is_red`` contract and returns a
    2-tuple ``(is_red, pattern_id)`` — so we interpret the FIRST element only
    (a 2-tuple ``(False, "")`` is itself truthy, which a naive ``if cb(raw):``
    would misread as always-RED). Defense-in-depth: if the callable raises, or
    returns an unexpected shape, treat it as not-RED (the safe direction: no
    downgrade, policy still applies). Never propagates.
    """
    try:
        result = red_check_callable(raw)
    except Exception:  # noqa: BLE001 — never let a callable break the resolver
        return False
    try:
        return bool(result[0])
    except Exception:  # noqa: BLE001 — unexpected return shape -> not RED
        return False


def _safe_lockout(self_lockout_checker_callable: Callable[[str], bool], raw: str) -> bool:
    """Invoke the self-lockout check, returning a plain bool.

    Contract: ``self_lockout_checker_callable(raw) -> bool`` (True = ``raw`` is
    on the never-self-lockout self-repair allowlist). Defense-in-depth: if it
    raises, treat as not-on-allowlist (the safe direction: no allow-exception).
    Never propagates.
    """
    try:
        return bool(self_lockout_checker_callable(raw))
    except Exception:  # noqa: BLE001 — never let a callable break the resolver
        return False


def resolve_error_policy(
    raw: str,
    error_policy: str,
    attended: bool,
    trigger: str,
    red_check_callable: Callable[[str], tuple[bool, str]] | None = None,
    self_lockout_checker_callable: Callable[[str], bool] | None = None,
    *,
    debug: bool = False,
) -> tuple[str, str]:
    """Resolve a ``cannot_evaluate`` situation to a TERMINAL decision.

    Args:
        raw: the raw command/path string under evaluation; passed verbatim to
            BOTH callables.
        error_policy: the configured tier — one of ``open`` / ``closed`` /
            ``ask`` / ``observe``. Anything else fails CLOSED (``deny``).
        attended: whether a human is present to answer an ``ask`` prompt. Only
            consulted in the ``ask`` tier.
        trigger: why evaluation failed — one of ``binary_missing`` /
            ``spawn_fail`` / ``timeout`` / ``nonzero_exit`` / ``unparseable``.
            METADATA ONLY: the decision is invariant across trigger values; this
            function never branches on it.
        red_check_callable: ``is_red``-shaped — ``(raw) -> (bool, str)``. Its
            FIRST element is the catastrophic-RED flag. In production (``debug``
            False) this MUST be wired.
        self_lockout_checker_callable: ``(raw) -> bool`` — True = ``raw`` is on
            the self-repair allowlist. In production this MUST be wired.
        debug: dev/test feature-flag. When False (the production default), BOTH
            callables MUST be non-None or a ``ValueError`` is raised (a None in
            production is a wiring bug — fail loudly). When True, a None callable
            is permitted and means that STEP is SKIPPED (skipping RED = no
            downgrade; skipping self-lockout = no allow-exception).

    Returns:
        A ``(decision, outcome_reason)`` tuple where ``decision`` is one of
        ``allow`` / ``ask`` / ``deny`` (always terminal — never
        ``cannot_evaluate``) and ``outcome_reason`` is one of the seven strings
        in :data:`OUTCOME_REASONS`.

    Raises:
        ValueError: only when ``debug`` is False and either callable is None
            (a production wiring bug; defense-in-depth alongside the adapters'
            own init-time assertions). This is the SOLE exception this function
            raises — it never propagates an exception from a callable.
    """
    if not debug:
        if red_check_callable is None or self_lockout_checker_callable is None:
            raise ValueError(
                "resolve_error_policy: in production (debug=False) BOTH "
                "red_check_callable and self_lockout_checker_callable MUST be "
                "wired; a None is a wiring bug (pass debug=True to skip a step "
                "in dev/test). "
                f"red_check_callable={red_check_callable!r}, "
                f"self_lockout_checker_callable={self_lockout_checker_callable!r}"
            )

    # 1) Self-lockout — highest precedence; the ONLY path that skips the RED
    #    check. A None checker (debug only) means: skip this step (no
    #    allow-exception, the safer direction).
    if self_lockout_checker_callable is not None and _safe_lockout(
        self_lockout_checker_callable, raw
    ):
        return ("allow", "allowed-selfrepair")

    # 2) Catastrophic-RED override — beats policy (even ``open`` / ``observe``).
    #    A None check (debug only) means: skip this step (no downgrade; policy
    #    still applies).
    if red_check_callable is not None and _safe_red(red_check_callable, raw):
        return ("deny", "denied-catastrophic-unevaluated")

    # 3) Policy tier. Unknown policy => fail CLOSED.
    if error_policy == "open":
        return ("allow", "allowed-unevaluated")
    if error_policy == "closed":
        return ("deny", "denied-unevaluated")
    if error_policy == "ask":
        if attended:
            return ("ask", "asked-unevaluated")
        return ("deny", "would-have-asked")
    if error_policy == "observe":
        return ("allow", "would-have-blocked")

    # Defensive: an unrecognized policy must never fall through to allow.
    return ("deny", "denied-unevaluated")
