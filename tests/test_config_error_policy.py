"""
test_config_error_policy.py — agent-shield Layer 7 (Configuration), error-path posture
======================================================================================

TDD spec for task E1: the FIVE error-path POSTURE fields on the frozen
``GuardConfig``, plus their matching ``AGENT_SHIELD_*`` env keys.

These are POSTURE fields only — they govern what the guard does when an
*evaluation cannot complete* (error path), and they NEVER relax a built-in
detection pattern (consistent with GuardConfig's "can never relax a built-in
pattern" design).

Scope (E1 only): fields + defaults + frozen + env keys + invalid->default+warning.
Explicitly NOT here (later tasks): range clamping of the timeouts (E2),
``detect_harness()`` / harness-specific defaults (E2), preset forcing (E3),
``health_probe`` re-probe semantics (E4).

Conventions mirrored from ``config.py`` / ``tests/test_config.py``:
  - loader entry point is ``config.load()`` (TOTAL — never raises);
  - enum validation via the existing ``_str_in``-style helper;
  - env bools via the existing truthy/falsy token set;
  - invalid value -> field DEFAULT + a surfaced ``UserWarning`` (never raise).

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import dataclasses

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


# The default values pinned by the E1 spec.
_DEFAULTS = {
    "error_policy": "closed",
    "unattended": False,
    "ask_timeout_ms": 60000,
    "spawn_timeout_ms": 5000,
    "health_probe": True,
}


# ===========================================================================
# (1) Each of the 5 fields exists on a default GuardConfig() with the exact default
# ===========================================================================
@pytest.mark.parametrize("field_name, expected", list(_DEFAULTS.items()))
def test_guard_field_default_value(field_name, expected):
    g = config.GuardConfig()
    assert hasattr(g, field_name), f"GuardConfig missing field {field_name!r}"
    actual = getattr(g, field_name)
    assert actual == expected
    # bools must be real bools (not 0/1), to keep posture explicit
    if isinstance(expected, bool):
        assert actual is expected


def test_guard_defaults_via_loaded_config():
    cfg = config.load()
    for field_name, expected in _DEFAULTS.items():
        actual = getattr(cfg.guard, field_name)
        assert actual == expected
        if isinstance(expected, bool):
            assert actual is expected


def test_error_policy_default_is_closed():
    # The NEUTRAL default (harness-specific defaults like CC=observe arrive in E2).
    assert config.GuardConfig().error_policy == "closed"


# ===========================================================================
# (2) GuardConfig is still frozen
# ===========================================================================
@pytest.mark.parametrize("field_name", list(_DEFAULTS))
def test_guard_is_frozen(field_name):
    g = config.GuardConfig()
    assert dataclasses.is_dataclass(g)
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(g, field_name, getattr(g, field_name))


# ===========================================================================
# (3) Each ENV key, when set to a valid value, is reflected in the loaded config
# ===========================================================================
def test_env_error_policy_valid(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "open")
    assert config.load().guard.error_policy == "open"


def test_env_unattended_valid(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_UNATTENDED", "true")
    assert config.load().guard.unattended is True


def test_env_unattended_falsy(monkeypatch):
    # default is False; set it via a falsy token and confirm it parses to a real bool
    monkeypatch.setenv("AGENT_SHIELD_UNATTENDED", "off")
    assert config.load().guard.unattended is False


def test_env_ask_timeout_valid(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", "120000")
    assert config.load().guard.ask_timeout_ms == 120000


def test_env_spawn_timeout_valid(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SPAWN_TIMEOUT_MS", "8000")
    assert config.load().guard.spawn_timeout_ms == 8000


def test_env_health_probe_valid(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_HEALTH_PROBE", "false")
    assert config.load().guard.health_probe is False


# An IN-RANGE int (within the E2 [1000, 600000] ask-timeout range) is accepted
# as-is with no warning. (Range validation itself — including the out-of-range
# default+warn path — is pinned in tests/test_config_harness.py for E2; this E1
# pin just confirms a plain in-range int round-trips cleanly.)
def test_int_that_parses_in_range_is_accepted_as_is(monkeypatch, recwarn):
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", "300000")
    cfg = config.load()
    assert cfg.guard.ask_timeout_ms == 300000
    assert len(recwarn) == 0


# ===========================================================================
# (4) An INVALID value for each env key -> default + UserWarning (never raise)
# ===========================================================================
def test_env_error_policy_invalid_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "explode")
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.error_policy == "closed"


def test_env_unattended_invalid_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_UNATTENDED", "maybe")
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.unattended is False


def test_env_ask_timeout_invalid_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ASK_TIMEOUT_MS", "soon")
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.ask_timeout_ms == 60000


def test_env_spawn_timeout_invalid_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SPAWN_TIMEOUT_MS", "12.5")  # float string -> not an int
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.spawn_timeout_ms == 5000


def test_env_health_probe_invalid_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_HEALTH_PROBE", "sometimes")
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.health_probe is True


# ===========================================================================
# (5) error_policy accepts each of open|closed|ask|observe; rejects bogus
# ===========================================================================
@pytest.mark.parametrize("value", ["open", "closed", "ask", "observe"])
def test_error_policy_accepts_each_valid_value(value, monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", value)
    assert config.load().guard.error_policy == value


def test_error_policy_rejects_bogus_value(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "lenient")
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.error_policy == "closed"


# ===========================================================================
# Plumbing: the new env keys are wired into the ENV_KEYS contract table
# (the same table the existing L7-API-1 drift pin checks against load()'s reads).
# ===========================================================================
@pytest.mark.parametrize("env_name, dotted", [
    ("AGENT_SHIELD_ERROR_POLICY", "guard.error_policy"),
    ("AGENT_SHIELD_UNATTENDED", "guard.unattended"),
    ("AGENT_SHIELD_ASK_TIMEOUT_MS", "guard.ask_timeout_ms"),
    ("AGENT_SHIELD_SPAWN_TIMEOUT_MS", "guard.spawn_timeout_ms"),
    ("AGENT_SHIELD_HEALTH_PROBE", "guard.health_probe"),
])
def test_new_env_keys_in_env_keys_table(env_name, dotted):
    assert config.ENV_KEYS.get(env_name) == dotted


# ===========================================================================
# Posture invariant: an empty/whitespace-only env value is treated as unset
# (mirrors the existing settings; no spurious warning), keeping the default.
# ===========================================================================
@pytest.mark.parametrize("var", [
    "AGENT_SHIELD_ERROR_POLICY", "AGENT_SHIELD_UNATTENDED",
    "AGENT_SHIELD_ASK_TIMEOUT_MS", "AGENT_SHIELD_SPAWN_TIMEOUT_MS",
    "AGENT_SHIELD_HEALTH_PROBE",
])
def test_empty_error_path_env_var_is_unset_no_warn(var, monkeypatch, recwarn):
    monkeypatch.setenv(var, "   ")
    cfg = config.load()
    for field_name, expected in _DEFAULTS.items():
        assert getattr(cfg.guard, field_name) == expected
    assert len(recwarn) == 0
