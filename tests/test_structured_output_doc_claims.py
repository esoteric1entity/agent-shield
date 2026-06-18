"""
test_structured_output_doc_claims.py — Layer 3 docs pinned to code
==================================================================

Mirrors test_sanitize_doc_claims / test_doc_claims: the supported-type /
constraint / mode inventory and the load-bearing semantic rules (int-vs-bool,
int->float widening, NaN rejection, MAX_DEPTH, path format) are pinned to the
code, and the honesty claims (shape != intent, canary is v0.2, never executes)
must be present while the over-claims must be absent.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_shield import structured_output as so

_ROOT = Path(so.__file__).resolve().parent.parent
README = (_ROOT / "README.md").read_text(encoding="utf-8")
DOC_PATH = _ROOT / "docs" / "STRUCTURED_OUTPUT.md"


def test_doc_exists():
    assert DOC_PATH.exists()


def test_supported_types_constraints_modes_pinned():
    doc = DOC_PATH.read_text(encoding="utf-8")
    for t in so.SUPPORTED_TYPES:
        assert t.__name__ in doc, f"supported type {t.__name__} not documented"
    for ck in so.CONSTRAINT_KINDS:
        assert ck in doc, f"constraint kind {ck} not documented"
    for m in so.MODES:
        assert m in doc, f"mode {m} not documented"
    # no fabricated count claim
    assert not re.search(r"\*\*\d+ (?:supported )?(?:types?|constraints?)\*\*", doc, re.I)


def test_doc_pins_type_rules_and_maxdepth_and_path():
    doc = DOC_PATH.read_text(encoding="utf-8").lower()
    assert "bool" in doc and "int" in doc            # int/bool disambiguation discussed
    assert "widen" in doc or "int->float" in doc or "whole number" in doc
    assert "nan" in doc or "infinity" in doc or "non-finite" in doc
    assert str(so.MAX_DEPTH) in DOC_PATH.read_text(encoding="utf-8")  # literal value pinned
    assert "$.args[2].name" in DOC_PATH.read_text(encoding="utf-8")   # path format pinned


def test_doc_states_shape_not_intent_canary_v02_never_executes():
    doc = DOC_PATH.read_text(encoding="utf-8").lower()
    blob = doc + README.lower()
    assert "shape" in doc and ("not intent" in doc or "not content" in doc or "intent" in doc)
    assert "canary" in doc and ("v0.2" in doc or "deferred" in doc or "response stream" in doc)
    assert "never execute" in doc or "does not execute" in doc or "never executes" in doc
    # over-claims must be absent from the shipped Layer 3 prose
    assert "anti-prompt-injection" not in blob
    assert "prevents injection" not in blob and "blocks injection" not in blob


def test_readme_layer3_flips_only_with_green_suite():
    assert "## Layer 3 — Structured Output" in README
    assert re.search(r"\|\s*3\s*\|\s*\*\*Structured Output\*\*.*✅", README)
    assert re.search(r"Layer 3 \(structured output\).*✅", README)
    assert re.search(r"Layers 1, 2, 3, 4, 6, and 7 ship", README)
    sec = README[README.index("## Layer 3 — Structured Output"):]
    sec = sec[:sec.index("\n## ", 1)] if "\n## " in sec[1:] else sec
    assert re.search(r"(?:shape, not|not intent|not content|does not validate)", sec.lower())
