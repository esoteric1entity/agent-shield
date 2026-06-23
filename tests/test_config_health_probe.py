"""
test_config_health_probe.py — agent-shield Layer 7 (Configuration), health-probe semantics
===========================================================================================

TDD spec for task E4: the ``health_probe`` field is a thin config-layer toggle;
the actual re-probe cadence / TTL / circuit-breaker lives in Phases C2/D2.

LOCKED semantics:
  - Default = ``True`` — a tripped circuit-breaker MAY perform periodic re-probes
    to detect guard recovery.
  - ``False`` — re-probing is disabled; the breaker stays tripped until the
    process/session restarts (OpenClaw module-level breaker) or the on-disk
    state is cleared (CC file-backed breaker).
  - **NO bootstrap grace** — the breaker denies from call 1; ``health_probe`` does
    NOT grant any "first N calls are free" leniency. It only controls whether
    recovery re-probes happen AFTER the initial trip.

This file pins the config-layer contract (field default, env wiring, invalid-
value handling) and the semantic constants that document the no-bootstrap-grace
rule. The actual breaker machinery is tested in Phases C2/D2.

Scope note (E1/E4): like ``unattended`` and the timeouts, ``health_probe`` is
env-only in v0.2. Only ``error_policy`` has a config-file tier at this stage.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import pytest

from agent_shield import config


# ---------------------------------------------------------------------------
# Isolation: fresh cwd + fake HOME with no AGENT_SHIELD_* env (mirrors
# tests/test_config.py::_clean_env).
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
# (1) Default and type
# ===========================================================================
def test_guard_config_health_probe_defaults_true():
    assert config.GuardConfig().health_probe is True


def test_loaded_config_health_probe_defaults_true():
    assert config.load().guard.health_probe is True


# ===========================================================================
# (2) Env override (env-only in v0.2)
# ===========================================================================
@pytest.mark.parametrize("token", ["false", "0", "no", "off"])
def test_env_health_probe_falsy_tokens(monkeypatch, token):
    monkeypatch.setenv("AGENT_SHIELD_HEALTH_PROBE", token)
    assert config.load().guard.health_probe is False


@pytest.mark.parametrize("token", ["true", "1", "yes", "on"])
def test_env_health_probe_truthy_tokens(monkeypatch, token):
    monkeypatch.setenv("AGENT_SHIELD_HEALTH_PROBE", token)
    assert config.load().guard.health_probe is True


# ===========================================================================
# (3) Invalid value -> default + warning (totality)
# ===========================================================================
def test_env_health_probe_invalid_falls_back_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_HEALTH_PROBE", "sometimes")
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.guard.health_probe is True


def test_empty_health_probe_env_is_unset_no_warn(monkeypatch, recwarn):
    monkeypatch.setenv("AGENT_SHIELD_HEALTH_PROBE", "   ")
    cfg = config.load()
    assert cfg.guard.health_probe is True
    assert len(recwarn) == 0


# ===========================================================================
# (4) Semantic contract pins (E4 — no bootstrap grace, re-probe toggle)
# ===========================================================================
def test_health_probe_default_constant_exists():
    """The default value is exported and documented as a config contract."""
    assert config.DEFAULT_HEALTH_PROBE is True


def test_health_probe_controls_reprobe_semantics_constant():
    """A semantic constant documents the locked E4 meaning of the toggle:
    when True, a tripped breaker MAY re-probe for recovery; when False, it
    MUST NOT. This is a config-layer contract; the breaker implements it."""
    assert hasattr(config, "HEALTH_PROBE_ENABLES_REPROBE")
    assert isinstance(config.HEALTH_PROBE_ENABLES_REPROBE, bool)
    assert config.HEALTH_PROBE_ENABLES_REPROBE is True


def test_no_bootstrap_grace_semantic_constant_exists():
    """A semantic constant documents the locked E4 no-bootstrap-grace rule:
    the breaker denies from call 1; health_probe only governs recovery re-probe."""
    assert hasattr(config, "HEALTH_PROBE_NO_BOOTSTRAP_GRACE")
    assert config.HEALTH_PROBE_NO_BOOTSTRAP_GRACE is True
