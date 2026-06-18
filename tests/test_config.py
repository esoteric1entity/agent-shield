"""
test_config.py — agent-shield Layer 7 (Configuration)
=====================================================

TDD spec for `agent_shield/config.py`: the cross-layer config loader + the
shared compliance contract. Written red-first against the Layer-7 design
(the Layer 7 configuration design) and the
adversarial pre-mortem (18 hazards; 8 must-fix). Hazard IDs (Hn) tag the test
that pins each mitigation.

Hard guarantees under test:
  - load() is TOTAL — never raises into a caller, for ANY input.
  - Presets mirror audit.PRESETS EXACTLY (general/healthcare/biotech); an
    unknown/typo'd preset can never reach AuditLog (which raises ValueError).
  - Precedence: built-in defaults < file < env < explicit kwargs.
  - Partial config inherits absent keys, never resets a preset's posture.
  - Config is NOT a trust boundary; it cannot weaken a built-in guard.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import dataclasses
import warnings

import pytest

from agent_shield import audit, config, structured_output


# ---------------------------------------------------------------------------
# Isolation: every test runs in a fresh cwd + fake HOME with no AGENT_SHIELD_*
# env, so `load()` with no file truly sees built-in defaults (not a real
# ~/.agent-shield/config.toml or a stray ./agent-shield.toml).
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _clean_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    for var in list(__import__("os").environ):
        if var.startswith("AGENT_SHIELD_"):
            monkeypatch.delenv(var, raising=False)


def _write(tmp_path, text, name="agent-shield.toml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ===========================================================================
# Group A: dataclasses, defaults, to_dict, frozen
# ===========================================================================
def test_defaults_no_config_present():
    cfg = config.load()
    assert cfg.compliance == "general"
    assert cfg.audit.retention_days == 90
    assert cfg.audit.fail_mode == "open"
    assert cfg.audit.content_fields_always is False
    assert cfg.sanitize.strict is False
    assert cfg.structured_output.mode == "strict"


def test_default_audit_path_is_expanded():
    cfg = config.load()
    assert "~" not in cfg.audit.path        # H14 — tilde expanded, never handed raw to AuditLog


def test_dataclasses_are_frozen():
    cfg = config.load()
    for obj in (cfg, cfg.audit, cfg.sanitize, cfg.structured_output, cfg.guard):
        assert dataclasses.is_dataclass(obj)
        with pytest.raises(dataclasses.FrozenInstanceError):
            object.__setattr__  # sanity: frozen set must raise
            setattr(obj, "compliance", "x")


def test_to_dict_round_shape():
    d = config.load().to_dict()
    assert d["compliance"] == "general"
    assert set(d) == {"compliance", "audit", "sanitize", "structured_output", "guard"}
    assert d["audit"]["retention_days"] == 90
    assert d["sanitize"]["strict"] is False
    assert d["structured_output"]["mode"] == "strict"


def test_config_is_constructible_into_auditlog(tmp_path):
    # The whole point of the contract: a loaded config feeds AuditLog without raising.
    cfg = config.load()
    log = audit.AuditLog(path=tmp_path / "a.jsonl", preset=cfg.compliance)
    assert log.preset == "general"


# ===========================================================================
# Group B: preset parity with audit (H1, H12)
# ===========================================================================
def test_preset_names_mirror_audit_exactly():       # H1/H12
    assert set(config.preset_names()) == set(audit.PRESETS)


def test_each_preset_derives_audit_fields_from_audit(tmp_path):   # H12
    for name in audit.PRESETS:
        cfg = config.load(compliance=name)
        spec = audit.PRESETS[name]
        assert cfg.audit.retention_days == spec["retention_days"]
        assert cfg.audit.fail_mode == spec["fail_mode"]
        assert cfg.audit.content_fields_always == spec["content_fields_always"]
        # and it must construct a real AuditLog
        audit.AuditLog(path=tmp_path / f"{name}.jsonl", preset=cfg.compliance)


def test_healthcare_preset_full_posture():
    cfg = config.load(compliance="healthcare")
    assert cfg.audit.retention_days == 365
    assert cfg.audit.fail_mode == "closed"
    assert cfg.audit.content_fields_always is True
    assert cfg.sanitize.strict is True            # healthcare tightens sanitize


# ===========================================================================
# Group C: unknown / typo'd compliance never crashes a caller (H1) — CRITICAL
# ===========================================================================
@pytest.mark.parametrize("bad", ["enterprise", "bogus", "Healthcare", "", "general "])
def test_unknown_compliance_falls_back_to_general_and_warns(bad, tmp_path):   # H1
    with pytest.warns(UserWarning):
        cfg = config.load(compliance=bad)
    assert cfg.compliance == "general"
    # must still build AuditLog (the never-crash payoff)
    audit.AuditLog(path=tmp_path / "x.jsonl", preset=cfg.compliance)


def test_unknown_compliance_in_file(tmp_path):       # H1 via file tier
    p = _write(tmp_path, 'compliance = "enterprise"\n')
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert cfg.compliance == "general"


# ===========================================================================
# Group D: load valid file + search path + precedence (AC)
# ===========================================================================
def test_load_valid_file(tmp_path):
    p = _write(tmp_path, 'compliance = "healthcare"\n[sanitize]\nstrict = true\n')
    cfg = config.load(path=p)
    assert cfg.compliance == "healthcare"
    assert cfg.sanitize.strict is True


def test_cwd_file_autodiscovered(tmp_path):
    _write(tmp_path, 'compliance = "biotech"\n')      # cwd is tmp_path (fixture)
    cfg = config.load()
    assert cfg.compliance == "biotech"


def test_env_config_path_override(tmp_path, monkeypatch):
    p = _write(tmp_path, 'compliance = "healthcare"\n', name="elsewhere.toml")
    monkeypatch.setenv("AGENT_SHIELD_CONFIG", str(p))
    cfg = config.load()
    assert cfg.compliance == "healthcare"


def test_empty_env_config_treated_as_unset(tmp_path, monkeypatch):    # H14
    monkeypatch.setenv("AGENT_SHIELD_CONFIG", "   ")
    cfg = config.load()
    assert cfg.compliance == "general"        # falls through, no crash


def test_precedence_kwarg_beats_env_beats_file(tmp_path, monkeypatch):   # AC precedence
    p = _write(tmp_path, 'compliance = "general"\n')
    monkeypatch.setenv("AGENT_SHIELD_CONFIG", str(p))
    monkeypatch.setenv("AGENT_SHIELD_COMPLIANCE", "biotech")
    # file=general, env=biotech, kwarg=healthcare -> kwarg wins
    cfg = config.load(compliance="healthcare")
    assert cfg.compliance == "healthcare"
    # drop the kwarg -> env wins
    cfg2 = config.load()
    assert cfg2.compliance == "biotech"


def test_env_overridable_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_COMPLIANCE", "healthcare")
    monkeypatch.setenv("AGENT_SHIELD_AUDIT_PATH", str(tmp_path / "x.jsonl"))
    monkeypatch.setenv("AGENT_SHIELD_STRUCTURED_OUTPUT_MODE", "lenient")
    cfg = config.load()
    assert cfg.compliance == "healthcare"
    assert cfg.audit.path == str(tmp_path / "x.jsonl")
    assert cfg.structured_output.mode == "lenient"


# ===========================================================================
# Group E: partial / deep merge — absent keys inherit, never reset (H4)
# ===========================================================================
def test_partial_file_keeps_preset_posture(tmp_path):    # H4
    # healthcare + a file that sets ONLY audit.path must keep fail_mode=closed,
    # retention=365, content=True, and sanitize.strict=True (preset default).
    p = _write(
        tmp_path,
        'compliance = "healthcare"\n[audit]\npath = "/custom/audit.jsonl"\n',
    )
    cfg = config.load(path=p)
    assert cfg.audit.fail_mode == "closed"
    assert cfg.audit.retention_days == 365
    assert cfg.audit.content_fields_always is True
    assert cfg.sanitize.strict is True
    assert cfg.audit.path.endswith("audit.jsonl")


# ===========================================================================
# Group F: never-crash — every malformed shape -> defaults + warning (H3,H13,H18)
# ===========================================================================
def test_malformed_toml_falls_back_and_warns(tmp_path):    # H3/H13
    p = _write(tmp_path, 'compliance = "healthcare\n')      # unterminated string
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert cfg.compliance == "general"


def test_duplicate_key_warns_with_path(tmp_path):          # H13
    p = _write(tmp_path, 'compliance = "general"\ncompliance = "healthcare"\n')
    with pytest.warns(UserWarning) as rec:
        cfg = config.load(path=p)
    assert cfg.compliance == "general"
    assert any(str(p) in str(w.message) or "agent-shield.toml" in str(w.message) for w in rec)


def test_path_is_a_directory(tmp_path):                    # H3/H18
    d = tmp_path / "cfgdir"
    d.mkdir()
    with pytest.warns(UserWarning):
        cfg = config.load(path=d)
    assert cfg.compliance == "general"


def test_non_utf8_file(tmp_path):                          # H3/H13
    p = tmp_path / "bad.toml"
    p.write_bytes(b'compliance = "\xff\xfe healthcare"\n')
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert cfg.compliance == "general"


def test_bom_prefixed_file_never_crashes(tmp_path):        # H13
    p = tmp_path / "bom.toml"
    p.write_bytes(b"\xef\xbb\xbf" + b'compliance = "healthcare"\n')
    # Contract is never-crash; tomllib rejects a leading BOM, so we fall back+warn.
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert isinstance(cfg, config.Config)


def test_oversized_file_skipped_fast(tmp_path):            # H18
    p = tmp_path / "huge.toml"
    p.write_bytes(b'compliance = "healthcare"\n' + b"# pad\n" * 400_000)  # > 1 MiB
    assert p.stat().st_size > config.MAX_CONFIG_BYTES
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert cfg.compliance == "general"


def test_missing_explicit_path_warns(tmp_path):
    with pytest.warns(UserWarning):
        cfg = config.load(path=tmp_path / "nope.toml")
    assert cfg.compliance == "general"


def test_missing_default_search_is_silent(recwarn):
    cfg = config.load()           # no file anywhere (clean fixture)
    assert cfg.compliance == "general"
    assert len(recwarn) == 0      # default-search legs missing -> silent


# ===========================================================================
# Group G: per-field type coercion -> default + warn (H3)
# ===========================================================================
def test_compliance_wrong_type_in_file(tmp_path):
    p = _write(tmp_path, "compliance = 5\n")
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert cfg.compliance == "general"


def test_audit_path_wrong_type_in_file(tmp_path):
    p = _write(tmp_path, "[audit]\npath = 42\n")
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert "~" not in cfg.audit.path
    assert cfg.audit.path.endswith("audit.jsonl")     # kept default


def test_strict_string_in_file_is_rejected_not_coerced(tmp_path):
    # `strict = "false"` (a STRING) must NOT silently parse; on healthcare it must
    # NOT downgrade the preset default (True). Mistyped -> warn + keep default.
    p = _write(tmp_path, 'compliance = "healthcare"\n[sanitize]\nstrict = "false"\n')
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert cfg.sanitize.strict is True               # preset default preserved


def test_invalid_mode_in_file(tmp_path):
    p = _write(tmp_path, '[structured_output]\nmode = "loose"\n')
    with pytest.warns(UserWarning):
        cfg = config.load(path=p)
    assert cfg.structured_output.mode == "strict"     # validated against MODES


def test_valid_lenient_mode(tmp_path):
    p = _write(tmp_path, '[structured_output]\nmode = "lenient"\n')
    cfg = config.load(path=p)
    assert cfg.structured_output.mode == "lenient"
    assert cfg.structured_output.mode in structured_output.MODES


# ===========================================================================
# Group H: env / kwarg string coercion (H8, H14)
# ===========================================================================
@pytest.mark.parametrize("raw", ["true", "1", "yes", "on", "TRUE", "On"])
def test_env_bool_truthy(raw, monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SANITIZE_STRICT", raw)
    assert config.load().sanitize.strict is True


@pytest.mark.parametrize("raw", ["false", "0", "no", "off", "FALSE", "Off"])
def test_env_bool_falsy(raw, monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SANITIZE_STRICT", raw)
    assert config.load().sanitize.strict is False


def test_env_bool_garbage_ignored_and_warns(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SANITIZE_STRICT", "maybe")
    with pytest.warns(UserWarning):
        cfg = config.load()
    assert cfg.sanitize.strict is False        # default kept


def test_kwarg_audit_path_tilde_expanded():
    cfg = config.load(audit_path="~/myaudit.jsonl")
    assert "~" not in cfg.audit.path
    assert cfg.audit.path.endswith("myaudit.jsonl")


def test_home_unset_does_not_crash(monkeypatch):
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.delenv("USERPROFILE", raising=False)
    cfg = config.load()
    assert isinstance(cfg, config.Config)


# ===========================================================================
# Group I: downgrade warning (H10)
# ===========================================================================
def test_explicit_downgrade_of_preset_strict_warns():     # H10
    with pytest.warns(UserWarning, match="(?i)downgrad|weaken|strict"):
        cfg = config.load(compliance="healthcare", sanitize_strict=False)
    assert cfg.sanitize.strict is False


def test_no_downgrade_warning_when_consistent(recwarn):
    cfg = config.load(compliance="general")        # general default strict=False, no override
    assert cfg.sanitize.strict is False
    assert len(recwarn) == 0


# ===========================================================================
# Group J: warnings are UserWarning, never DeprecationWarning (H8)
# ===========================================================================
def test_valid_load_emits_no_deprecationwarning(tmp_path):    # H8/H16
    p = _write(tmp_path, 'compliance = "healthcare"\n')
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        cfg = config.load(path=p)
    assert cfg.compliance == "healthcare"


def test_malformed_load_emits_no_deprecationwarning(tmp_path):   # H8
    p = _write(tmp_path, "compliance = \n")     # malformed
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        warnings.simplefilter("ignore", UserWarning)
        cfg = config.load(path=p)
    assert cfg.compliance == "general"


# ===========================================================================
# Group K: config is NOT a trust boundary — cannot weaken a guard (H2)
# ===========================================================================
def test_config_has_no_guard_pattern_injection_keys(tmp_path):    # H2/H6
    # v0.1 must NOT expose extra_red/extra_yellow (dead, policy-weakening keys).
    p = _write(tmp_path, '[bash_guard]\nextra_red = ["rm -rf /"]\n[guard]\nextra_yellow = ["x"]\n')
    cfg = config.load(path=p)                 # unknown keys ignored, no crash
    assert not hasattr(cfg.guard, "extra_red")
    assert not hasattr(cfg.guard, "extra_yellow")


def test_no_config_input_can_drop_a_red_bash_command(tmp_path):    # H2
    from agent_shield import bash_guard
    p = _write(tmp_path, '[bash_guard]\nextra_red = []\ncompliance = "general"\n')
    config.load(path=p)                       # whatever the config says...
    # ...a built-in RED command is still denied (guards don't read config in v0.1).
    assert bash_guard.check_command("rm -rf /").decision == "deny"


# ===========================================================================
# Group L: packaging / lazy import / import hygiene (H5, H16, H17)
# ===========================================================================
def test_config_in_all():
    import agent_shield
    assert "config" in agent_shield.__all__


def test_tomllib_available_under_floor():       # H17
    import tomllib       # noqa: F401 — must import cleanly on the >=3.12 floor
    assert hasattr(tomllib, "load")


def test_config_imports_are_stdlib_only():      # H16
    import ast
    from pathlib import Path
    src = Path(config.__file__).read_text(encoding="utf-8")
    allowed = {"tomllib", "os", "pathlib", "dataclasses", "typing",
               "warnings", "__future__", "agent_shield"}
    roots = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    assert roots <= allowed, f"unexpected imports in config.py: {roots - allowed}"


# ===========================================================================
# Group M: adversarial-review fixes
# NC-1 warn-guard; PREC-2/L7-XL-02 env strip+empty; L7-XL-03 / L7-API-1 drift pins.
# ===========================================================================
@pytest.mark.parametrize("kwargs", [
    {"compliance": "bogus"},                              # unknown preset (inner warn)
    {"compliance": "healthcare", "sanitize_strict": False},  # downgrade warn
])
def test_total_even_under_global_warnings_as_errors(kwargs):   # NC-1
    # A caller running `-W error` (warnings promoted to exceptions) must NOT be
    # able to break load()'s never-raise contract on a degrade path.
    with warnings.catch_warnings():
        warnings.simplefilter("error")          # ALL warnings -> exceptions
        cfg = config.load(**kwargs)             # must NOT raise
    assert isinstance(cfg, config.Config)


def test_total_under_warnings_error_for_malformed_file(tmp_path):   # NC-1
    p = _write(tmp_path, "compliance = \n")     # malformed
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        cfg = config.load(path=p)
    assert cfg.compliance == "general"


def test_env_enum_trailing_whitespace_tolerated(monkeypatch):   # PREC-2
    monkeypatch.setenv("AGENT_SHIELD_COMPLIANCE", "healthcare ")   # trailing space
    assert config.load().compliance == "healthcare"


@pytest.mark.parametrize("var", [
    "AGENT_SHIELD_COMPLIANCE", "AGENT_SHIELD_AUDIT_PATH",
    "AGENT_SHIELD_SANITIZE_STRICT", "AGENT_SHIELD_STRUCTURED_OUTPUT_MODE",
])
def test_empty_setting_env_var_is_unset_no_warn(var, monkeypatch, recwarn):   # L7-XL-02
    monkeypatch.setenv(var, "   ")              # exported-but-empty
    cfg = config.load()
    assert cfg.compliance == "general"
    assert len(recwarn) == 0                    # treated as unset, not a spurious warning


def test_default_mode_is_a_valid_mode():        # L7-XL-03
    assert config.DEFAULT_MODE in structured_output.MODES


def test_env_keys_table_matches_what_load_reads():   # L7-API-1 (R2-ENV-1: also catch raw reads)
    import ast
    from pathlib import Path
    src = Path(config.__file__).read_text(encoding="utf-8")
    read = set()

    def _str_arg(node):
        return (node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)) and node.args[0].value or None

    for node in ast.walk(ast.parse(src)):
        # settings read via the _env_setting() helper
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_env_setting":
            v = _str_arg(node)
            if v:
                read.add(v)
        # ALSO any RAW os.environ.get(...) / os.getenv(...) of an AGENT_SHIELD_ setting var
        # (other than the separate CONFIG_PATH_ENV file-path var) — a stray bypass of the helper
        # is drift the pin must flag (R2-ENV-1).
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            fn = node.func
            is_environ_get = (fn.attr == "get" and isinstance(fn.value, ast.Attribute)
                              and fn.value.attr == "environ")
            is_getenv = (fn.attr == "getenv" and isinstance(fn.value, ast.Name) and fn.value.id == "os")
            if is_environ_get or is_getenv:
                v = _str_arg(node)
                if v and v.startswith("AGENT_SHIELD_") and v != config.CONFIG_PATH_ENV:
                    read.add(v)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
            sl = node.slice
            if (isinstance(sl, ast.Constant) and isinstance(sl.value, str)
                    and sl.value.startswith("AGENT_SHIELD_") and sl.value != config.CONFIG_PATH_ENV):
                read.add(sl.value)

    assert read == set(config.ENV_KEYS), (
        f"ENV_KEYS table drifted from the env vars load() actually reads: "
        f"table={set(config.ENV_KEYS)} read={read}"
    )


def test_path_surrounding_whitespace_stripped_then_expanded():   # L7R2-DOC-1
    # The doc promises "a leading ~ is expanded"; surrounding whitespace must be
    # stripped first so the tilde is at index 0 (all tiers agree with the env tier).
    cfg = config.load(audit_path="  ~/myaudit.jsonl  ")
    assert "~" not in cfg.audit.path
    assert cfg.audit.path == cfg.audit.path.strip()
    assert cfg.audit.path.endswith("myaudit.jsonl")


def test_file_path_surrounding_whitespace_stripped(tmp_path):    # L7R2-DOC-1
    p = _write(tmp_path, '[audit]\npath = "  ~/fileaudit.jsonl  "\n')
    cfg = config.load(path=p)
    assert "~" not in cfg.audit.path
    assert cfg.audit.path == cfg.audit.path.strip()
