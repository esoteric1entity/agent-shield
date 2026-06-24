"""
test_error_policy_resolver.py — the error-path resolver (v0.2 task B3)
=====================================================================

``resolve_error_policy()`` is the single place that turns a "the guard could
not evaluate this action" situation (a ``cannot_evaluate``) into a TERMINAL
decision (allow / ask / deny), based on:

  1. a never-self-lockout check (highest precedence — the only path that skips
     the catastrophic-RED check),
  2. a catastrophic-RED override (beats policy),
  3. the configured ``error_policy`` tier (open / closed / ask / observe),
     modulated by ``attended`` for the ``ask`` tier.

It is PURE logic: it imports neither the guards nor the allowlist — both the
RED check and the self-lockout check are RECEIVED as callables (no import
cycle). The resolver NEVER returns ``cannot_evaluate`` (it RESOLVES it) and
NEVER propagates an exception from a callable.

``trigger`` is METADATA ONLY: the decision MUST be invariant across all
trigger values. The full policy × attended × trigger matrix below proves that
invariance (the same (decision, outcome_reason) for every trigger).

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import pytest

from agent_shield._error_policy import resolve_error_policy

# The five documented triggers — metadata only; never change the decision.
_TRIGGERS = ("binary_missing", "spawn_fail", "timeout", "nonzero_exit", "unparseable")

# A representative raw command/path under evaluation.
_RAW = "rm -rf /"


# ------------------------------------------------------------------ doubles
def _red(_raw):
    """is_red test double: a RED hit. 2-tuple (bool, pattern_id)."""
    return (True, "destructive_rm")


def _not_red(_raw):
    """is_red test double: not RED. 2-tuple (False, "")."""
    return (False, "")


def _lockout(_raw):
    """self-lockout test double: raw IS on the self-repair allowlist."""
    return True


def _not_lockout(_raw):
    """self-lockout test double: raw is NOT on the allowlist."""
    return False


def _raises(_raw):
    """A callable that raises — the resolver must treat its result as False."""
    raise RuntimeError("callable blew up")


# ============================================================
# Full matrix: policy × attended × trigger, non-RED / non-lockout path.
# Proves trigger-invariance (decision + outcome_reason fixed per policy/attended,
# identical across all five triggers).
# ============================================================
#
# expected (decision, outcome_reason) keyed by (error_policy, attended):
_MATRIX = {
    ("open", True): ("allow", "allowed-unevaluated"),
    ("open", False): ("allow", "allowed-unevaluated"),
    ("closed", True): ("deny", "denied-unevaluated"),
    ("closed", False): ("deny", "denied-unevaluated"),
    ("ask", True): ("ask", "asked-unevaluated"),
    ("ask", False): ("deny", "would-have-asked"),
    ("observe", True): ("allow", "would-have-blocked"),
    ("observe", False): ("allow", "would-have-blocked"),
}

_MATRIX_CASES = [
    (policy, attended, trigger, expected)
    for (policy, attended), expected in _MATRIX.items()
    for trigger in _TRIGGERS
]


@pytest.mark.parametrize("policy,attended,trigger,expected", _MATRIX_CASES)
def test_policy_attended_trigger_matrix(policy, attended, trigger, expected):
    """4 policies × 2 attended × 5 triggers = 40 cases.

    Asserts BOTH the decision and the outcome_reason. Because every trigger
    yields the SAME expected tuple per (policy, attended), this proves the
    resolver does not branch on ``trigger``.
    """
    decision, outcome = resolve_error_policy(
        raw=_RAW,
        error_policy=policy,
        attended=attended,
        trigger=trigger,
        red_check_callable=_not_red,
        self_lockout_checker_callable=_not_lockout,
    )
    assert (decision, outcome) == expected


@pytest.mark.parametrize("policy,attended", list(_MATRIX.keys()))
def test_trigger_invariance_explicit(policy, attended):
    """Stronger invariance pin: collect the result for ALL five triggers and
    assert they are byte-identical (one distinct tuple)."""
    results = {
        resolve_error_policy(
            raw=_RAW,
            error_policy=policy,
            attended=attended,
            trigger=trigger,
            red_check_callable=_not_red,
            self_lockout_checker_callable=_not_lockout,
        )
        for trigger in _TRIGGERS
    }
    assert len(results) == 1, f"trigger changed the decision for {(policy, attended)}: {results}"


# ============================================================
# Precedence: self-lockout BEATS RED BEATS policy.
# ============================================================

@pytest.mark.parametrize("policy", ["open", "closed", "ask", "observe"])
@pytest.mark.parametrize("attended", [True, False])
def test_self_lockout_beats_everything(policy, attended):
    """raw that is BOTH RED and self-lockout -> allow / allowed-selfrepair,
    regardless of policy or attendedness (self-lockout is highest precedence
    and is the ONLY path that skips the RED check)."""
    decision, outcome = resolve_error_policy(
        raw=_RAW,
        error_policy=policy,
        attended=attended,
        trigger="binary_missing",
        red_check_callable=_red,          # RED would otherwise deny
        self_lockout_checker_callable=_lockout,
    )
    assert (decision, outcome) == ("allow", "allowed-selfrepair")


@pytest.mark.parametrize("policy", ["open", "closed", "ask", "observe"])
@pytest.mark.parametrize("attended", [True, False])
@pytest.mark.parametrize("trigger", _TRIGGERS)
def test_red_beats_policy(policy, attended, trigger):
    """A RED raw (not on the self-repair allowlist) -> deny /
    denied-catastrophic-unevaluated, beating EVERY policy (even ``open`` and
    ``observe``) and invariant across triggers."""
    decision, outcome = resolve_error_policy(
        raw=_RAW,
        error_policy=policy,
        attended=attended,
        trigger=trigger,
        red_check_callable=_red,
        self_lockout_checker_callable=_not_lockout,
    )
    assert (decision, outcome) == ("deny", "denied-catastrophic-unevaluated")


def test_red_under_open_still_denies():
    """Spec spotlight: a RED raw under error_policy='open' is STILL a deny."""
    assert resolve_error_policy(
        raw=_RAW,
        error_policy="open",
        attended=True,
        trigger="timeout",
        red_check_callable=_red,
        self_lockout_checker_callable=_not_lockout,
    ) == ("deny", "denied-catastrophic-unevaluated")


# ============================================================
# Callable RETURN-SHAPE contract: red_check returns a 2-TUPLE.
# A (False, "") must NOT be misread as truthy -> always-RED bug.
# ============================================================

def test_red_check_false_tuple_is_not_treated_as_red():
    """is_red returning (False, "") (a truthy tuple!) must fall through to
    policy, NOT deny-as-catastrophic. Guards against `if red_check(raw):`."""
    decision, outcome = resolve_error_policy(
        raw=_RAW,
        error_policy="open",
        attended=True,
        trigger="timeout",
        red_check_callable=_not_red,      # returns (False, "")
        self_lockout_checker_callable=_not_lockout,
    )
    assert (decision, outcome) == ("allow", "allowed-unevaluated")


def test_red_check_first_element_is_what_matters():
    """Only the FIRST tuple element decides RED — a non-empty pattern_id with a
    False flag is still not-RED."""
    def _false_with_id(_raw):
        return (False, "looks_scary_but_false")

    decision, outcome = resolve_error_policy(
        raw=_RAW,
        error_policy="closed",
        attended=True,
        trigger="timeout",
        red_check_callable=_false_with_id,
        self_lockout_checker_callable=_not_lockout,
    )
    assert (decision, outcome) == ("deny", "denied-unevaluated")  # policy, not catastrophic


# ============================================================
# All 7 outcome strings produced by at least one case (explicit pins).
# ============================================================

_ALL_SEVEN = {
    "allowed-selfrepair",
    "denied-catastrophic-unevaluated",
    "allowed-unevaluated",
    "denied-unevaluated",
    "asked-unevaluated",
    "would-have-asked",
    "would-have-blocked",
}


def test_outcome_allowed_selfrepair():
    assert resolve_error_policy(
        _RAW, "closed", True, "timeout",
        red_check_callable=_red, self_lockout_checker_callable=_lockout,
    )[1] == "allowed-selfrepair"


def test_outcome_denied_catastrophic():
    assert resolve_error_policy(
        _RAW, "open", True, "timeout",
        red_check_callable=_red, self_lockout_checker_callable=_not_lockout,
    )[1] == "denied-catastrophic-unevaluated"


def test_outcome_allowed_unevaluated():
    assert resolve_error_policy(
        _RAW, "open", False, "timeout",
        red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout,
    )[1] == "allowed-unevaluated"


def test_outcome_denied_unevaluated():
    assert resolve_error_policy(
        _RAW, "closed", True, "timeout",
        red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout,
    )[1] == "denied-unevaluated"


def test_outcome_asked_unevaluated():
    assert resolve_error_policy(
        _RAW, "ask", True, "timeout",
        red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout,
    )[1] == "asked-unevaluated"


def test_outcome_would_have_asked():
    assert resolve_error_policy(
        _RAW, "ask", False, "timeout",
        red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout,
    )[1] == "would-have-asked"


def test_outcome_would_have_blocked():
    assert resolve_error_policy(
        _RAW, "observe", True, "timeout",
        red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout,
    )[1] == "would-have-blocked"


def test_all_seven_outcomes_are_reachable():
    """Belt-and-suspenders: drive the resolver across cases and assert the union
    of produced outcome_reasons covers all 7 documented strings exactly."""
    produced = set()
    # selfrepair
    produced.add(resolve_error_policy(_RAW, "closed", True, "timeout",
                 red_check_callable=_red, self_lockout_checker_callable=_lockout)[1])
    # catastrophic
    produced.add(resolve_error_policy(_RAW, "open", True, "timeout",
                 red_check_callable=_red, self_lockout_checker_callable=_not_lockout)[1])
    # policy tiers
    produced.add(resolve_error_policy(_RAW, "open", True, "timeout",
                 red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout)[1])
    produced.add(resolve_error_policy(_RAW, "closed", True, "timeout",
                 red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout)[1])
    produced.add(resolve_error_policy(_RAW, "ask", True, "timeout",
                 red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout)[1])
    produced.add(resolve_error_policy(_RAW, "ask", False, "timeout",
                 red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout)[1])
    produced.add(resolve_error_policy(_RAW, "observe", True, "timeout",
                 red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout)[1])
    assert produced == _ALL_SEVEN


def test_decisions_are_always_terminal():
    """The resolver NEVER returns cannot_evaluate — every result is terminal."""
    for policy, attended in _MATRIX:
        decision, _ = resolve_error_policy(
            _RAW, policy, attended, "timeout",
            red_check_callable=_not_red, self_lockout_checker_callable=_not_lockout,
        )
        assert decision in {"allow", "ask", "deny"}


# ============================================================
# debug=True: None callables => that STEP is skipped (documented dev/test flag).
#   - skipping RED   = no downgrade (policy still applies)
#   - skipping lockout = no allow-exception (safer direction)
# ============================================================

@pytest.mark.parametrize(
    "policy,attended,expected",
    [
        ("open", True, ("allow", "allowed-unevaluated")),
        ("closed", True, ("deny", "denied-unevaluated")),
        ("ask", True, ("ask", "asked-unevaluated")),
        ("ask", False, ("deny", "would-have-asked")),
        ("observe", True, ("allow", "would-have-blocked")),
    ],
)
def test_debug_both_callables_none_falls_to_policy(policy, attended, expected):
    """debug=True with BOTH callables None: RED-step and lockout-step skipped,
    decision falls straight to the policy tier."""
    assert resolve_error_policy(
        raw=_RAW,
        error_policy=policy,
        attended=attended,
        trigger="timeout",
        red_check_callable=None,
        self_lockout_checker_callable=None,
        debug=True,
    ) == expected


def test_debug_none_red_check_means_no_downgrade():
    """debug=True, red_check=None: a raw that WOULD be RED is not downgraded —
    policy applies (here open -> allow)."""
    assert resolve_error_policy(
        raw=_RAW,
        error_policy="open",
        attended=True,
        trigger="timeout",
        red_check_callable=None,                  # RED step skipped
        self_lockout_checker_callable=_not_lockout,
        debug=True,
    ) == ("allow", "allowed-unevaluated")


def test_debug_none_lockout_means_no_allow_exception():
    """debug=True, self_lockout=None: no allow-exception is granted (safer
    direction) — a RED raw still denies-catastrophic."""
    assert resolve_error_policy(
        raw=_RAW,
        error_policy="open",
        attended=True,
        trigger="timeout",
        red_check_callable=_red,
        self_lockout_checker_callable=None,       # lockout step skipped
        debug=True,
    ) == ("deny", "denied-catastrophic-unevaluated")


def test_debug_true_with_both_callables_wired_still_works():
    """debug=True does not REQUIRE None — wired callables still function."""
    assert resolve_error_policy(
        raw=_RAW,
        error_policy="closed",
        attended=True,
        trigger="timeout",
        red_check_callable=_lockout and _not_red,  # not-red
        self_lockout_checker_callable=_lockout,
        debug=True,
    ) == ("allow", "allowed-selfrepair")


# ============================================================
# debug=False (production default): BOTH callables MUST be wired.
# A None => ValueError (a wiring bug must fail loudly).
# ============================================================

def test_debug_false_none_red_check_raises_valueerror():
    with pytest.raises(ValueError):
        resolve_error_policy(
            raw=_RAW,
            error_policy="open",
            attended=True,
            trigger="timeout",
            red_check_callable=None,
            self_lockout_checker_callable=_not_lockout,
        )


def test_debug_false_none_self_lockout_raises_valueerror():
    with pytest.raises(ValueError):
        resolve_error_policy(
            raw=_RAW,
            error_policy="open",
            attended=True,
            trigger="timeout",
            red_check_callable=_not_red,
            self_lockout_checker_callable=None,
        )


def test_debug_false_both_none_raises_valueerror():
    with pytest.raises(ValueError):
        resolve_error_policy(
            raw=_RAW,
            error_policy="open",
            attended=True,
            trigger="timeout",
            red_check_callable=None,
            self_lockout_checker_callable=None,
        )


def test_debug_false_default_kwarg_omitted_none_raises():
    """The default (debug omitted) is the production path — None still raises."""
    with pytest.raises(ValueError):
        resolve_error_policy(_RAW, "closed", False, "spawn_fail", None, _not_lockout)


# ============================================================
# Never-raise on a callable error (defense-in-depth).
# A raising callable is treated as False and the resolver CONTINUES.
# ============================================================

def test_red_check_raises_is_treated_as_not_red():
    """red_check raising -> treated as not-RED -> fall through to policy."""
    assert resolve_error_policy(
        raw=_RAW,
        error_policy="open",
        attended=True,
        trigger="timeout",
        red_check_callable=_raises,
        self_lockout_checker_callable=_not_lockout,
    ) == ("allow", "allowed-unevaluated")


def test_self_lockout_raises_is_treated_as_not_on_allowlist():
    """self_lockout raising -> treated as not-on-allowlist (no allow-exception);
    a RED raw therefore still denies-catastrophic."""
    assert resolve_error_policy(
        raw=_RAW,
        error_policy="open",
        attended=True,
        trigger="timeout",
        red_check_callable=_red,
        self_lockout_checker_callable=_raises,
    ) == ("deny", "denied-catastrophic-unevaluated")


def test_both_callables_raise_no_exception_propagates():
    """Both raising -> both treated as False -> resolver still returns a
    terminal decision (policy applies)."""
    decision, outcome = resolve_error_policy(
        raw=_RAW,
        error_policy="closed",
        attended=True,
        trigger="timeout",
        red_check_callable=_raises,
        self_lockout_checker_callable=_raises,
    )
    assert (decision, outcome) == ("deny", "denied-unevaluated")


def test_self_lockout_raises_does_not_skip_red():
    """A raising lockout check must not accidentally grant the allow-exception;
    RED evaluation still runs (and here, denies)."""
    decision, _ = resolve_error_policy(
        raw=_RAW,
        error_policy="open",
        attended=True,
        trigger="binary_missing",
        red_check_callable=_red,
        self_lockout_checker_callable=_raises,
    )
    assert decision == "deny"


def test_base_exception_from_callable_propagates():
    """``except Exception`` (NOT ``except BaseException``) is INTENTIONAL: a
    ``KeyboardInterrupt`` / ``SystemExit`` from a callable MUST propagate so the
    resolver stays interruptible and never swallows a shutdown signal. This pins
    the boundary — a future ``except BaseException`` slip would make this
    security chokepoint un-interruptible with a still-green suite."""

    def _kbint(_raw):
        raise KeyboardInterrupt

    def _sysexit(_raw):
        raise SystemExit(1)

    # KeyboardInterrupt from the RED check (step 2) propagates.
    with pytest.raises(KeyboardInterrupt):
        resolve_error_policy(
            _RAW, "closed", True, "timeout",
            red_check_callable=_kbint, self_lockout_checker_callable=_not_lockout,
        )
    # SystemExit from the self-lockout check (step 1) propagates.
    with pytest.raises(SystemExit):
        resolve_error_policy(
            _RAW, "closed", True, "timeout",
            red_check_callable=_not_red, self_lockout_checker_callable=_sysexit,
        )


# ============================================================
# Defensive: unknown error_policy => fail CLOSED (deny / denied-unevaluated).
# ============================================================

@pytest.mark.parametrize("bad_policy", ["", "OPEN", "Closed", "allow", "block", "unknown", "asky"])
def test_unknown_error_policy_fails_closed(bad_policy):
    assert resolve_error_policy(
        raw=_RAW,
        error_policy=bad_policy,
        attended=True,
        trigger="timeout",
        red_check_callable=_not_red,
        self_lockout_checker_callable=_not_lockout,
    ) == ("deny", "denied-unevaluated")


def test_unknown_policy_still_honors_selfrepair_and_red_precedence():
    """Even with a bad policy, self-lockout and RED precedence hold (they run
    BEFORE the policy tier)."""
    # self-lockout wins
    assert resolve_error_policy(
        _RAW, "garbage", True, "timeout",
        red_check_callable=_red, self_lockout_checker_callable=_lockout,
    ) == ("allow", "allowed-selfrepair")
    # RED wins over a bad policy
    assert resolve_error_policy(
        _RAW, "garbage", True, "timeout",
        red_check_callable=_red, self_lockout_checker_callable=_not_lockout,
    ) == ("deny", "denied-catastrophic-unevaluated")


# ============================================================
# raw is passed THROUGH to both callables (wiring sanity).
# ============================================================

def test_raw_is_passed_to_both_callables():
    seen = {}

    def _red_spy(raw):
        seen["red"] = raw
        return (False, "")

    def _lockout_spy(raw):
        seen["lockout"] = raw
        return False

    resolve_error_policy(
        raw="custom-raw-string",
        error_policy="closed",
        attended=True,
        trigger="timeout",
        red_check_callable=_red_spy,
        self_lockout_checker_callable=_lockout_spy,
    )
    assert seen["lockout"] == "custom-raw-string"
    assert seen["red"] == "custom-raw-string"
