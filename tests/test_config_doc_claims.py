"""
test_config_doc_claims.py — pin docs/CONFIGURATION.md to the code.

Every concrete claim the Layer-7 doc makes (preset names, the settable field
list, the env-var surface, the honesty/limitation statements) is asserted
against the live code constants so the doc cannot silently drift from reality.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from agent_shield import audit, config, structured_output

_DOC = (Path(config.__file__).resolve().parent.parent / "docs" / "CONFIGURATION.md").read_text(
    encoding="utf-8"
)


def test_preset_names_match_audit_and_are_documented():
    names = set(config.preset_names())
    assert names == set(audit.PRESETS)                 # code single-source parity
    for name in names:
        assert name in _DOC, f"preset {name!r} not documented in CONFIGURATION.md"


def test_strict_sanitize_compliance_is_subset_of_presets():
    # The cross-layer strict-sanitize policy may only name real presets.
    assert config.STRICT_SANITIZE_COMPLIANCE <= set(config.preset_names())


def test_settable_field_names_documented():
    leaf_fields = set()
    for dc in (config.AuditConfig, config.SanitizeConfig, config.StructuredOutputConfig):
        leaf_fields |= {f.name for f in dataclasses.fields(dc)}
    leaf_fields.add("compliance")
    for name in leaf_fields:
        assert name in _DOC, f"config field {name!r} not documented"


def test_env_vars_documented():
    for env_name in (config.CONFIG_PATH_ENV, *config.ENV_KEYS):
        assert env_name in _DOC, f"env var {env_name!r} not documented"


def test_modes_documented():
    for mode in structured_output.MODES:
        assert mode in _DOC


def test_honesty_and_limitation_claims_present():
    # not a trust boundary; the env-pointed location is unguardable; YAML rejected.
    assert "not a trust boundary" in _DOC.lower()
    assert config.CONFIG_PATH_ENV in _DOC                       # the unguardable-location note names it
    assert "yaml" in _DOC.lower()
    assert "secret" in _DOC.lower()                             # "no secrets" guidance


def test_precedence_order_documented():
    low = _DOC.lower()
    for token in ("default", "file", "environment", "keyword"):
        assert token in low, f"precedence token {token!r} missing from CONFIGURATION.md"


def test_shared_contract_documented():     # L7-XL-01 — the design names this doc for it
    # Decision/GuardResult is the cross-layer shared contract the spine documents.
    assert "GuardResult" in _DOC
    assert "Decision" in _DOC
    assert "MAX_CONFIG_BYTES" in _DOC      # DOC-1 — the concrete size limit is stated
