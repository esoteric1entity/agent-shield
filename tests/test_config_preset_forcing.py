"""
test_config_preset_forcing.py — agent-shield Layer 7 (Configuration), preset forcing
=====================================================================================

TDD spec for task E3 (Contract #4 + the MED clarification): a **tightening**
compliance preset FORCES ``guard.error_policy = "closed"`` at the TOP of
precedence — above the harness-default, the config file, the env var, and any
explicit input.

The tightening presets are the ones that already tighten posture elsewhere
(``audit.fail_mode == "closed"`` / strict sanitization):

    healthcare, biotech

(confirmed from ``agent_shield.audit.PRESETS`` — the single source config mirrors;
these are exactly the members of ``config.STRICT_SANITIZE_COMPLIANCE``.)

Behavior (LOCKED):
  - When the active preset is tightening, the resolved ``error_policy`` is FORCED
    to ``"closed"`` regardless of what the normal E2 ladder (built-in <
    harness-default < file < env) resolved.
  - If the E2 ladder resolved something OTHER than ``"closed"`` (i.e. an
    open/observe/ask override was supplied via file or env), that override is
    IGNORED and a ``UserWarning`` is emitted stating the preset forces closed.
  - If the E2 ladder already resolved ``"closed"`` (no override attempt, or an
    explicit ``closed``), NO warning is emitted.
  - A NON-tightening preset (``general``) or no preset does NOT force anything —
    the E2 ladder result stands.

Decoupling (LOCKED): ``audit.fail_mode`` (the preset-derived audit field) is
DECOUPLED from ``error_policy`` — error_policy forcing must NOT mutate it. They
happen to share the value ``"closed"`` for the tightening presets, but for
different reasons and via different code paths.

Explicitly NOT here: ``health_probe`` re-probe semantics (E4).

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import pytest

from agent_shield import config


# ---------------------------------------------------------------------------
# Isolation: fresh cwd + fake HOME with no AGENT_SHIELD_* env (mirrors
# tests/test_config.py::_clean_env) so load() with no file sees built-in
# defaults, not a stray real config file or inherited env override. Also pin a
# neutral argv0 so detect_harness()-style argv leakage cannot perturb defaults.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _clean_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr("sys.argv", ["pytest"])
    for var in list(__import__("os").environ):
        if var.startswith("AGENT_SHIELD_"):
            monkeypatch.delenv(var, raising=False)


# The presets config accepts; confirms the tightening set is what E3 forces.
TIGHTENING = ("healthcare", "biotech")


# ===========================================================================
# (0) The tightening-preset set matches the audit presets with fail_mode=closed
#     (and equals STRICT_SANITIZE_COMPLIANCE) — pins the "which presets" decision.
# ===========================================================================
def test_tightening_presets_are_healthcare_and_biotech():
    assert set(TIGHTENING) == set(config.STRICT_SANITIZE_COMPLIANCE)
    # and they are real presets config accepts
    for name in TIGHTENING:
        assert name in config.preset_names()


# ===========================================================================
# (1) tightening preset + an env override -> forced "closed" + UserWarning
# ===========================================================================
def test_healthcare_env_open_override_forced_closed_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "open")
    with pytest.warns(UserWarning):
        cfg = config.load(compliance="healthcare")
    assert cfg.guard.error_policy == "closed"


@pytest.mark.parametrize("preset", TIGHTENING)
@pytest.mark.parametrize("override", ["open", "observe", "ask"])
def test_tightening_preset_any_non_closed_env_override_forced(preset, override, monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", override)
    with pytest.warns(UserWarning):
        cfg = config.load(compliance=preset)
    assert cfg.guard.error_policy == "closed"


# ===========================================================================
# (2) tightening preset + a config-FILE override -> forced "closed" + UserWarning
# ===========================================================================
def test_biotech_file_observe_override_forced_closed_and_warns(tmp_path, monkeypatch):
    p = tmp_path / "agent-shield.toml"
    p.write_text('[guard]\nerror_policy = "observe"\n', encoding="utf-8")
    with pytest.warns(UserWarning):
        cfg = config.load(path=p, compliance="biotech")
    assert cfg.guard.error_policy == "closed"


# Forcing applies even when the compliance preset itself arrives from the env tier.
def test_tightening_preset_from_env_forces_over_file_override(tmp_path, monkeypatch):
    p = tmp_path / "agent-shield.toml"
    p.write_text('[guard]\nerror_policy = "open"\ncompliance = "general"\n', encoding="utf-8")
    monkeypatch.setenv("AGENT_SHIELD_COMPLIANCE", "healthcare")
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert cfg.guard.error_policy == "closed"


# Forcing applies even when the compliance preset itself arrives from the file tier.
def test_tightening_preset_from_file_forces_over_env_override(tmp_path, monkeypatch):
    p = tmp_path / "agent-shield.toml"
    p.write_text('compliance = "biotech"\n[guard]\nerror_policy = "ask"\n', encoding="utf-8")
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "ask")
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert cfg.guard.error_policy == "closed"


# Forcing beats even a harness-default that resolved to a non-closed value
# (claude_code -> observe). No file/env override, but the resolved ladder value
# is "observe" (an effective override of "closed"), so it is forced + warned.
def test_tightening_preset_forces_over_claude_code_harness_default(monkeypatch):
    with pytest.warns(UserWarning):
        cfg = config.load(compliance="healthcare", harness="claude_code")
    assert cfg.guard.error_policy == "closed"


# ===========================================================================
# (3) tightening preset, NO error_policy override (default) -> "closed", NO warn
#     With no harness hint the ladder already resolves the neutral "closed", so
#     forcing is a no-op and must NOT warn (nothing was overridden).
# ===========================================================================
@pytest.mark.parametrize("preset", TIGHTENING)
def test_tightening_preset_no_override_is_closed_no_warn(preset, recwarn):
    cfg = config.load(compliance=preset)
    assert cfg.guard.error_policy == "closed"
    assert len(recwarn) == 0


# ===========================================================================
# (4) tightening preset + EXPLICITLY closed env -> "closed", NO warn
#     (an explicit "closed" is not an override attempt to a non-closed value).
# ===========================================================================
def test_healthcare_explicit_closed_env_no_warn(monkeypatch, recwarn):
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "closed")
    cfg = config.load(compliance="healthcare")
    assert cfg.guard.error_policy == "closed"
    assert len(recwarn) == 0


def test_biotech_explicit_closed_file_no_warn(tmp_path, recwarn):
    p = tmp_path / "agent-shield.toml"
    p.write_text('[guard]\nerror_policy = "closed"\n', encoding="utf-8")
    cfg = config.load(path=p, compliance="biotech")
    assert cfg.guard.error_policy == "closed"
    assert len(recwarn) == 0


# ===========================================================================
# (5) NON-tightening / no preset + a non-closed override -> NOT forced (stands)
# ===========================================================================
def test_general_preset_open_env_not_forced(monkeypatch, recwarn):
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "open")
    cfg = config.load(compliance="general")
    assert cfg.guard.error_policy == "open"   # ladder result stands; not forced
    assert len(recwarn) == 0


def test_no_preset_open_env_not_forced(monkeypatch, recwarn):
    # No compliance kwarg -> DEFAULT_COMPLIANCE ("general"), a non-tightening preset.
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "open")
    cfg = config.load()
    assert cfg.guard.error_policy == "open"
    assert len(recwarn) == 0


def test_general_preset_observe_via_harness_not_forced(monkeypatch, recwarn):
    # claude_code harness default observe + general preset -> observe stands.
    cfg = config.load(compliance="general", harness="claude_code")
    assert cfg.guard.error_policy == "observe"
    assert len(recwarn) == 0


# ===========================================================================
# (6) DECOUPLING — error_policy forcing does NOT touch audit.fail_mode and the
#     other guard fields, and a NON-tightening preset's audit.fail_mode is also
#     governed solely by the preset (not by error_policy).
# ===========================================================================
@pytest.mark.parametrize("preset", TIGHTENING)
def test_tightening_preset_audit_fail_mode_unchanged_by_forcing(preset, monkeypatch):
    # Even with a non-closed error_policy override that gets forced, audit.fail_mode
    # is driven by the preset alone (the audit preset field), independent of the
    # error_policy code path.
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "open")
    with pytest.warns(UserWarning):
        cfg = config.load(compliance=preset)
    assert cfg.audit.fail_mode == "closed"   # preset-derived (audit.PRESETS), not error_policy


def test_general_preset_audit_fail_mode_is_open_even_with_closed_error_policy(monkeypatch):
    # The reverse decoupling direction: a "closed" error_policy must not push the
    # non-tightening preset's audit.fail_mode to "closed" (it stays the preset's "open").
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "closed")
    cfg = config.load(compliance="general")
    assert cfg.guard.error_policy == "closed"
    assert cfg.audit.fail_mode == "open"     # general preset's audit fail_mode


def test_tightening_forcing_does_not_touch_other_guard_fields(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "open")
    with pytest.warns(UserWarning):
        cfg = config.load(compliance="healthcare")
    assert cfg.guard.unattended is False
    assert cfg.guard.ask_timeout_ms == 60000
    assert cfg.guard.spawn_timeout_ms == 5000
    assert cfg.guard.health_probe is True


# ===========================================================================
# (7) Totality — forcing + its warning must not raise even under warnings-as-errors
#     (the never-raise contract: a caller's -W error cannot turn the force-warning
#     into a raise, mirroring the rest of config).
# ===========================================================================
def test_forcing_is_total_under_warnings_as_errors(monkeypatch):
    import warnings as _w
    monkeypatch.setenv("AGENT_SHIELD_ERROR_POLICY", "open")
    with _w.catch_warnings():
        _w.simplefilter("error")
        cfg = config.load(compliance="healthcare")   # must NOT raise
    assert cfg.guard.error_policy == "closed"
