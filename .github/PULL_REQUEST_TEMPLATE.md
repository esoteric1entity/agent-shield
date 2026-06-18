<!--
Thank you for contributing to agent-shield!

Before submitting:
- Read CONTRIBUTING.md if you have not yet
- Sign the CLA (the bot will guide you on first PR)
- Make sure your commits follow Conventional Commits + are DCO-signed (`git commit -s`)
-->

## Summary

<!-- One paragraph: what does this PR do and why? -->

## Type of change

- [ ] Bug fix (does not change public API)
- [ ] New feature (adds a pattern, layer, or API surface)
- [ ] Documentation only
- [ ] Refactor (no functional change)
- [ ] Test infrastructure
- [ ] Other:

## Layer affected

<!-- Mark the layer this PR touches. If multiple, list them. -->

- [ ] Layer 0 — Operational / Automation
- [ ] Layer 1 — Skill / Tool Vetting
- [ ] Layer 2 — Input Sanitization
- [ ] Layer 3 — Structured Output
- [ ] Layer 4 — Runtime Hooks
- [ ] Layer 5 — Network Egress
- [ ] Layer 6 — Structured Audit
- [ ] Layer 7 — Configuration
- [ ] Cross-layer

## Test plan

- [ ] `python -m pytest tests/` passes
- [ ] `bash tests/run_sh_tests.sh` passes (if you touched bash sources or Python ports)
- [ ] `python tests/run_equivalence_test.py` passes (if you touched Layer 4)
- [ ] New patterns have test cases for both `deny`/`ask`/`allow` decisions where applicable
- [ ] No regression — full suite remains green

## Threat model

<!-- For new patterns or behavior changes: what is the adversary, and what new
attack does this defend against (or what false positive does this fix)? -->

## Checklist

- [ ] My changes follow the coding style described in `CONTRIBUTING.md`
- [ ] I have added or updated tests covering my changes
- [ ] I have updated documentation (README, docstrings, CHANGELOG)
- [ ] I have signed my commits (`git commit -s`)
- [ ] I have signed the CLA
- [ ] This is NOT a security vulnerability disclosure (see SECURITY.md if it is)

## Related issues / advisories

<!-- Closes #N, related to #N, refs GHSA-####-####-#### -->
