"""
test_config_harness.py — agent-shield Layer 7 (Configuration), harness defaults
================================================================================

TDD spec for task E2 (Contract #4): harness detection + the harness-default tier
in the precedence ladder, plus timeout RANGE validation (deferred from E1).

Three things under test:

  (1) ``detect_harness() -> str | None`` — a module-level helper returning
      ``"openclaw"`` | ``"claude_code"`` | ``None``. Branch order (LOCKED):
        (a) ``AGENT_SHIELD_HARNESS`` env var (recognized value wins; an
            unrecognized value warns + is treated as unset, mirroring E1's
            invalid-handling pattern);
        (b) a conservative ``sys.argv[0]`` heuristic (the installed console-script
            basenames — ``agent-shield-openclaw-guard`` -> openclaw, the CC
            PreToolUse hook entries ``agent-shield-bash-guard`` /
            ``agent-shield-write-guard`` -> claude_code);
        (c) ``None``.
      Never raises.

  (2) ``harness=`` keyword-only kwarg on ``config.load`` — the adapters will later
      call ``detect_harness()`` and pass the hint.

  (3) The harness-default tier in the precedence ladder (Contract #4, LOCKED):
        built-in defaults < HARNESS-DEFAULT(kwarg) < config file < env < kwargs
      It sets the DEFAULT ``error_policy`` per harness BEFORE file/env/kwarg can
      override it:
        - harness="openclaw"     -> error_policy default = "closed"
        - harness="claude_code"  -> error_policy default = "observe"
        - harness=None / bogus   -> error_policy default = "closed" (neutral)
      An env var / explicit kwarg STILL overrides the harness default.

  (4) Timeout RANGE validation (E1 deferred this to E2):
        ask_timeout_ms   in [1000, 600000]
        spawn_timeout_ms in [1000, 60000]
      An in-range int is accepted; an OUT-OF-RANGE int -> field DEFAULT +
      ``UserWarning`` (mirrors E1's invalid-value handling; NOT silently clamped).
      A non-int still -> default + warning (E1 behavior, kept).

Explicitly NOT here (later tasks): preset forcing (healthcare/biotech -> force
``closed`` over ALL tiers) is E3; ``health_probe`` re-probe semantics is E4.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import pytest

from agent_shield import config


# ---------------------------------------------------------------------------
# Isolation: fresh cwd + fake HOME with no AGENT_SHIELD_* env (mirrors
# tests/test_config.py::_clean_env) so load() with no file sees built-in
# defaults, not a stray real config file or inherited env override.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _clean_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    for var in list(__import__("os").environ):
        if var.startswith("AGENT_SHIELD_"):
            monkeypatch.delenv(var, raising=False)


# ===========================================================================
# (1) detect_harness() — env-var branch (a)
# ===========================================================================
def test_detect_harness_env_openclaw(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_HARNESS", "openclaw")
    assert config.detect_harness() == "openclaw"


def test_detect_harness_env_claude_code(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_HARNESS", "claude_code")
    assert config.detect_harness() == "claude_code"


def test_detect_harness_env_trailing_whitespace_tolerated(monkeypatch):
    # env normalization mirrors the rest of config (strip surrounding whitespace).
    monkeypatch.setenv("AGENT_SHIELD_HARNESS", "openclaw ")
    assert config.detect_harness() == "openclaw"


def test_detect_harness_env_unrecognized_warns_and_treated_as_unset(monkeypatch):
    # An unrecognized value must NOT be honored; it warns + is treated as unset,
    # then the heuristic/None path runs. With a neutral argv0 -> None.
    monkeypatch.setenv("AGENT_SHIELD_HARNESS", "weirdtool")
    monkeypatch.setattr("sys.argv", ["pytest"])
    with pytest.warns(UserWarning):
        result = config.detect_harness()
    assert result is None


def test_detect_harness_env_empty_is_unset_no_warn(monkeypatch, recwarn):
    # Empty/whitespace-only env value treated as unset (mirrors existing settings).
    monkeypatch.setenv("AGENT_SHIELD_HARNESS", "   ")
    monkeypatch.setattr("sys.argv", ["pytest"])
    result = config.detect_harness()
    assert result is None
    assert len(recwarn) == 0


# ===========================================================================
# (1) detect_harness() — argv0 heuristic branch (b)
# ===========================================================================
@pytest.mark.parametrize("argv0", [
    "agent-shield-openclaw-guard",
    "/usr/local/bin/agent-shield-openclaw-guard",
    r"C:\Python\Scripts\agent-shield-openclaw-guard.exe",
])
def test_detect_harness_argv0_openclaw(argv0, monkeypatch):
    monkeypatch.delenv("AGENT_SHIELD_HARNESS", raising=False)
    monkeypatch.setattr("sys.argv", [argv0])
    assert config.detect_harness() == "openclaw"


@pytest.mark.parametrize("argv0", [
    "agent-shield-bash-guard",
    "agent-shield-write-guard",
    "/usr/local/bin/agent-shield-bash-guard",
    r"C:\Python\Scripts\agent-shield-write-guard.exe",
])
def test_detect_harness_argv0_claude_code(argv0, monkeypatch):
    monkeypatch.delenv("AGENT_SHIELD_HARNESS", raising=False)
    monkeypatch.setattr("sys.argv", [argv0])
    assert config.detect_harness() == "claude_code"


def test_detect_harness_env_wins_over_argv0(monkeypatch):
    # Env-var branch (a) takes precedence over the argv0 heuristic (b).
    monkeypatch.setenv("AGENT_SHIELD_HARNESS", "claude_code")
    monkeypatch.setattr("sys.argv", ["agent-shield-openclaw-guard"])
    assert config.detect_harness() == "claude_code"


# ===========================================================================
# (1) detect_harness() — neither -> None branch (c)
# ===========================================================================
@pytest.mark.parametrize("argv0", [
    "pytest",
    "python",
    "/usr/bin/python3",
    "",                       # empty argv0
    "some-unrelated-tool",
])
def test_detect_harness_none_when_no_signal(argv0, monkeypatch):
    monkeypatch.delenv("AGENT_SHIELD_HARNESS", raising=False)
    monkeypatch.setattr("sys.argv", [argv0])
    assert config.detect_harness() is None


def test_detect_harness_empty_argv_does_not_raise(monkeypatch):
    monkeypatch.delenv("AGENT_SHIELD_HARNESS", raising=False)
    monkeypatch.setattr("sys.argv", [])
    assert config.detect_harness() is None        # never raises


@pytest.mark.parametrize("argv0", [
    "my-agent-shield-openclaw-guard-wrapper",
    "agent-shield-openclaw-guard-helper",
    "agent-shield-bash-guard-extra",
    "xagent-shield-write-guard",
    "/opt/wrap/agent-shield-openclaw-guard-shim",
])
def test_detect_harness_argv0_substring_does_not_false_match(argv0, monkeypatch):
    # Conservatism (spec): only an EXACT basename (optionally ``.exe``) matches.
    # A wrapper name that merely CONTAINS a console-script name must NOT be
    # detected as that harness (else a wrong error_policy default could be seeded).
    monkeypatch.delenv("AGENT_SHIELD_HARNESS", raising=False)
    monkeypatch.setattr("sys.argv", [argv0])
    assert config.detect_harness() is None


# ===========================================================================
# (2)+(3) harness= kwarg sets the DEFAULT error_policy per harness
# ===========================================================================
def test_load_harness_openclaw_defaults_closed(monkeypatch):
    monkeypatch.setattr("sys.argv", ["pytest"])
    assert config.load(harness="openclaw").guard.error_policy == "closed"


def test_load_harness_claude_code_defaults_observe(monkeypatch):
    monkeypatch.setattr("sys.argv", ["pytest"])
    assert config.load(harness="claude_code").guard.error_policy == "observe"


def test_load_harness_none_defaults_closed(monkeypatch):
    monkeypatch.setattr("sys.argv", ["pytest"])
    assert config.load(harness=None).guard.error_policy == "closed"


def test_load_no_harness_kwarg_defaults_closed(monkeypatch):
    # Omitting the kwarg entirely keeps the neutral default (no auto-detect at
    # load() — the adapters detect and pass the hint).
    monkeypatch.setattr("sys.argv", ["pytest"])
    assert config.load().guard.error_policy == "closed"


def test_load_harness_unrecognized_defaults_closed_no_raise(monkeypatch):
    # A bogus harness hint -> neutral "closed" default (never raises).
    monkeypatch.setattr("sys.argv", ["pytest"])
    assert config.load(harness="bogus").guard.error_policy == "closed"


# Non-error_policy guard fields are unaffected by the harness hint.
def test_load_harness_does_not_touch_other_guard_fields(monkeypatch):
    monkeypatch.setattr("sys.argv", ["pytest"])
    cfg = config.load(harness="claude_code")
    assert cfg.guard.unattended is False
    assert cfg.guard.ask_timeout_ms == 60000
    assert cfg.guard.spawn_timeout_ms == 5000
    assert cfg.guard.health_probe is True


# ===========================================================================
# (3) env / kwarg STILL overrides the harness default (higher tier)
# ===========================================================================
def test_env_error_policy_overrides_harness_default(monkeypatch):
    # claude_code -> harness default observe, but env says closed -> closed wins.
    monkeypatch.setattr("sys.argv", ["pytest"])
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "closed")
    assert config.load(harness="claude_code").guard.error_policy == "closed"


def test_env_error_policy_overrides_openclaw_harness_default(monkeypatch):
    # openclaw -> harness default closed, but env says observe -> observe wins.
    monkeypatch.setattr("sys.argv", ["pytest"])
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "observe")
    assert config.load(harness="openclaw").guard.error_policy == "observe"


def test_file_error_policy_overrides_harness_default(tmp_path, monkeypatch):
    # A config file's guard.error_policy outranks the harness default tier.
    monkeypatch.setattr("sys.argv", ["pytest"])
    p = tmp_path / "agent-shield.toml"
    p.write_text("[guard]\nerror_policy = \"open\"\n", encoding="utf-8")
    assert config.load(path=p, harness="claude_code").guard.error_policy == "open"


def test_env_error_policy_beats_file_error_policy(tmp_path, monkeypatch):
    # The env tier outranks the file tier for guard.error_policy.
    monkeypatch.setattr("sys.argv", ["pytest"])
    p = tmp_path / "agent-shield.toml"
    p.write_text("[guard]\nerror_policy = \"open\"\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "ask")
    cfg = config.load(path=p, harness="claude_code")
    assert cfg.guard.error_policy == "ask"


def test_invalid_env_error_policy_falls_back_to_harness_default(monkeypatch):
    # An invalid env value warns + falls through; the next-lower tier is the
    # HARNESS default (observe for claude_code), NOT the neutral "closed".
    monkeypatch.setattr("sys.argv", ["pytest"])
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "explode")
    with pytest.warns(UserWarning):
        cfg = config.load(harness="claude_code")
    assert cfg.guard.error_policy == "observe"


# ===========================================================================
# (4) Timeout RANGE validation — ask_timeout_ms in [1000, 600000]
# ===========================================================================
def test_ask_timeout_in_range_accepted(monkeypatch, recwarn):
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", "120000")
    cfg = config.load()
    assert cfg.guard.ask_timeout_ms == 120000
    assert len(recwarn) == 0


@pytest.mark.parametrize("boundary", ["1000", "600000"])
def test_ask_timeout_boundaries_accepted(boundary, monkeypatch, recwarn):
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", boundary)
    cfg = config.load()
    assert cfg.guard.ask_timeout_ms == int(boundary)
    assert len(recwarn) == 0


def test_ask_timeout_below_min_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", "999")   # < 1000
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.ask_timeout_ms == 60000                   # field default


def test_ask_timeout_above_max_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", "600001")  # > 600000
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.ask_timeout_ms == 60000


def test_ask_timeout_non_int_still_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", "soon")
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.ask_timeout_ms == 60000


def test_ask_timeout_float_string_falls_back_and_warns(monkeypatch):
    # A float string is NOT a base-10 int and must be rejected (not truncated).
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", "12.5")
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.ask_timeout_ms == 60000


# ===========================================================================
# (4) Timeout RANGE validation — spawn_timeout_ms in [1000, 60000]
# ===========================================================================
def test_spawn_timeout_in_range_accepted(monkeypatch, recwarn):
    monkeypatch.setenv("AGENT_SHIELD_SPAWN_TIMEOUT_MS", "8000")
    cfg = config.load()
    assert cfg.guard.spawn_timeout_ms == 8000
    assert len(recwarn) == 0


@pytest.mark.parametrize("boundary", ["1000", "60000"])
def test_spawn_timeout_boundaries_accepted(boundary, monkeypatch, recwarn):
    monkeypatch.setenv("AGENT_SHIELD_SPAWN_TIMEOUT_MS", boundary)
    cfg = config.load()
    assert cfg.guard.spawn_timeout_ms == int(boundary)
    assert len(recwarn) == 0


def test_spawn_timeout_below_min_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SPAWN_TIMEOUT_MS", "999")   # < 1000
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.spawn_timeout_ms == 5000                    # field default


def test_spawn_timeout_above_max_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SPAWN_TIMEOUT_MS", "60001")  # > 60000
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.spawn_timeout_ms == 5000


def test_spawn_timeout_non_int_still_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SPAWN_TIMEOUT_MS", "12.5")   # float str -> not int
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.spawn_timeout_ms == 5000


# A range-rejected env value falls back to the field DEFAULT, never raises (totality).
def test_out_of_range_timeout_is_total_under_warnings_as_errors(monkeypatch):
    import warnings as _w
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", "1")        # below min
    with _w.catch_warnings():
        _w.simplefilter("error")                                 # warnings -> exceptions
        cfg = config.load()                                      # must NOT raise
    assert cfg.guard.ask_timeout_ms == 60000


# ===========================================================================
# Module-level range constants are exported (pinned contract).
# ===========================================================================
def test_timeout_range_constants_exist():
    assert config.ASK_TIMEOUT_MS_RANGE == (1000, 600000)
    assert config.SPAWN_TIMEOUT_MS_RANGE == (1000, 60000)


# ===========================================================================
# Harness default-policy map is exported (pinned contract).
# ===========================================================================
def test_harness_default_error_policy_map():
    assert config.HARNESS_ERROR_POLICY_DEFAULT["openclaw"] == "closed"
    assert config.HARNESS_ERROR_POLICY_DEFAULT["claude_code"] == "observe"
