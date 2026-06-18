"""
test_sanitize_doc_claims.py — Layer 2 docs are pinned to code, not aspirations
==============================================================================

Mirrors test_doc_claims.py / test_audit.py's doc-honesty suite. Two drift
guards: (1) the sub-layer ID list and the Finding-kind TAXONOMY are pinned to
the code constants (NOT a brittle marker COUNT — phrasings churn, kinds don't);
(2) the honest qualifiers (detection != prevention, integrator-must-honor-
delimiters, encoding-never-decodes, homoglyph-best-effort) must be present, and
the README status only flips 🟡→✅ when the section + negative claims exist.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_shield import sanitize

_ROOT = Path(sanitize.__file__).resolve().parent.parent
README = (_ROOT / "README.md").read_text(encoding="utf-8")
DOC_PATH = _ROOT / "docs" / "SANITIZATION.md"


def test_sanitization_doc_exists():
    assert DOC_PATH.exists(), "docs/SANITIZATION.md is referenced by sanitize.py and must exist"


def test_sublayer_ids_match_doc_and_count_says_four():
    doc = DOC_PATH.read_text(encoding="utf-8")
    assert len(sanitize.SUBLAYER_IDS) == 4
    for sid in sanitize.SUBLAYER_IDS:
        assert sid in doc, f"sub-layer id {sid!r} not documented in SANITIZATION.md"
    # the sub-layer COUNT claim is pinned to the layer's own doc (README also says
    # '8-layer' for the whole stack, so don't pin a bare '(\d+)-layer' there).
    assert re.search(r"\b(?:four|4)\b[\s\-]*sub", doc, re.I)


def test_kind_taxonomy_documented_no_fabricated_count():
    doc = DOC_PATH.read_text(encoding="utf-8")
    for kind in sanitize.ALL_KINDS:
        assert kind in doc, f"Finding kind {kind!r} not documented in SANITIZATION.md"
    # negative: no fabricated 'N injection patterns/markers' count (mirrors the
    # GREEN-pattern guard) — phrasings are heuristic and must not be counted in prose.
    assert not re.search(r"\*\*\d+ (?:injection|marker|jailbreak) patterns?\*\*", doc, re.I)


def test_doc_says_detection_not_prevention():
    blob = (DOC_PATH.read_text(encoding="utf-8") + README).lower()
    assert "detect" in blob
    assert "attacker cost" in blob
    assert re.search(r"(?:does not|doesn't|not a).{0,40}(?:block|prevent|guarantee)", blob)
    assert "novel" in blob or "unbounded" in blob


def test_doc_states_integrator_must_honor_delimiters():
    doc = DOC_PATH.read_text(encoding="utf-8").lower()
    assert "nonce" in doc
    assert "consuming prompt" in doc or "integrator" in doc or "only helps if" in doc


def test_doc_states_encoding_heuristic_and_homoglyph_best_effort():
    doc = DOC_PATH.read_text(encoding="utf-8").lower()
    assert "never decode" in doc or "does not decode" in doc or "not decoded" in doc
    assert "best-effort" in doc or "best effort" in doc
    assert "confusables" in doc            # honest about the missing TR39 table


def test_readme_structural_names_the_widened_strip_families():
    """The README Layer 2 section must name the BIDI directional marks and the
    WORD JOINER family (the deny-set widening that review caught the
    README omitting) — so a future widening can't leave the README stale-but-green."""
    sec = README[README.index("## Layer 2 — Input Sanitization"):].lower()
    sec = sec[:sec.index("\n## ", 1)] if "\n## " in sec[1:] else sec
    assert "directional" in sec      # LRM/RLM/ALM marks
    assert "joiner" in sec           # WORD JOINER (and the invisible-math/interlinear family)


def test_readme_layer2_row_flips_only_with_green_suite():
    assert "## Layer 2 — Input Sanitization" in README
    # 8-layers table + project-status table both ✅, not 🟡
    assert re.search(r"\|\s*2\s*\|\s*\*\*Input Sanitization\*\*.*✅", README)
    assert re.search(r"Layer 2 \(input sanitization\).*✅", README)
    # v0.1.0 summary line lists 2 among shipped layers
    assert re.search(r"Layers 1, 2, .*6, and 7 ship", README)  # '3' added w/ Layer 3; '7' added w/ Layer 7
    # the new section carries an honesty negative-claim
    sec = README[README.index("## Layer 2 — Input Sanitization"):]
    sec = sec[:sec.index("\n## ", 1)] if "\n## " in sec[1:] else sec
    assert re.search(r"(?:does not|doesn't|not).{0,40}(?:block|prevent)", sec.lower())
