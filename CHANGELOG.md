# Changelog — agent-shield

All notable changes to this package will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries describe user-facing changes at release granularity. Detailed
per-finding engineering notes are kept in the project's internal records.

---

## [Unreleased]

### Deferred to v0.2
Triaged as polish rather than blockers; deferred so each gets its own design and test pass:
- **L1 `ENV_BULK`** — also flag bulk `process.env` / `os.environ` reads (`Object.entries(process.env)`, `{...process.env}`, `os.environ.items()/values()/keys()`).
- **L1 typosquat scope** — extend manifest coverage beyond `requirements.txt` / `package.json` (e.g. `pyproject.toml`, `setup.py`, `Pipfile`, `environment.yml`) and/or allow edit-distance ≤ 2.
- **L6 egress AST lint** — also track `os` aliases, `from os import …`, `__import__`, and `importlib`.
- **L6 `Anchor` zero-cadence footgun** — warn (or raise) when both `every_n=0` and `every_minutes=0` but a sink/shipper is supplied (anchoring is silently disabled).
- **L7 `STRICT_SANITIZE_COMPLIANCE`** — derive sanitize strictness from a preset attribute, to close a forward-compat gap for a future high-posture preset.
- **Packaging** — a PEP-562 module `__getattr__` so `agent_shield.bash_guard` resolves after a bare `import agent_shield` while keeping the no-eager-import property.
- **L1 `skill_vetting` walker DoS hardening** — bound symlink / junction traversal to the target tree and add an aggregate file-count / total-byte budget so a hostile package can't soft-DoS the scan. (The vetter is a deliberately-invoked CLI, not an automated input path, so this is bounded-priority — it warrants its own design + test pass rather than a pre-flip change.)

## [0.1.0a4] — 2026-06-17 — readiness-hardening alpha

### Security & readiness hardening
Hardening from an independent adversarial review: cases the suite had not previously exercised were found and closed, each test-first, with the two Layer-4 ports kept decision-equivalent.

**Test suite after this hardening: 918 tests, all green; Python↔bash decision-equivalence 125/125.**

- **L4 `write_guard` — self-protection bypasses closed.** Path normalization now collapses redundant separators and resolves `.`/`..` dot-segments, so spellings that resolve to a guarded file (`agent_shield//bash_guard.py`, `/./`, `/x/../`, `x/.claude//settings.json`, `home/.ssh//id_rsa`, `.openclaw//.env`) can no longer dodge the `$`-anchored RED patterns. Mirrored in the bash source, with a degraded sed fallback for the no-Python case.
- **L4 `bash_guard` — wrapping / fork-bomb / rm-root bypasses closed.** A shell-invocation / `eval` / `xargs` lead-in is now treated as a command introducer, so a destructive verb inside `bash -c '…'` / `eval …` / `xargs …` is caught; the fork-bomb matcher is whitespace-tolerant; the `rm -rf /` (and `~` / `$HOME` / `.` / `..`) trailing sets now include shell metacharacters, so `rm -rf /; …` no longer downgrades to YELLOW. Mirrored in the bash source.
- **L4 `bash_guard` — recursive-force flag-cluster bypasses closed.** `rm` deletes of critical targets now deny for any flag bundling/ordering that contains both `-r` and `-f` — `rm -rfv /`, `rm -fvr /`, reordered clusters, and split forms where a token carries an extra letter (`rm -rv -f /`, `rm -r -fv /`) — and an end-of-options `--` or an intervening flag before the target no longer downgrades the block, uniformly across root / quoted-root / home / parent / Windows targets. Bounded matchers keep it ReDoS-safe. Mirrored in the bash source.
- **L1 `skill_vetting` — input-edge correctness.** An empty path no longer scans the CWD; a path that exists but is a device/pipe (`NUL`, `/dev/null`) returns `review` instead of `approved`; and the `agent-shield-vet` CLI emits its report as UTF-8 without mutating the caller's stdout encoding, so it neither crashes on an OEM/non-UTF-8 Windows console nor surprises an in-process embedder of `main()`.
- **Supply chain — Actions pinned to commit SHAs.** Every `actions/*` and `softprops/action-gh-release` step in the CI/release workflows is pinned to a full commit SHA (with a `# vX` comment); `pypa/gh-action-pypi-publish` intentionally stays on the publisher-recommended `release/v1` ref, gated by the `pypi` Environment protection rule. A `dependabot.yml` keeps the pins current.
- **Docs.** The audit canonical-serialization snippet now shows `allow_nan=False`, matching the code.
- **L4 — py↔bash whitespace parity; `chmod 777` widened; input-size cap.** All `bash_guard` patterns compile with `re.ASCII` so `\s` / `\w` / `\b` match the grep mirror's ASCII classes exactly; `chmod 777` now covers `-R` / split / verbose flags and octal `0777`, command-anchored; oversized input short-circuits to a conservative `ask` (never a silent `allow`), mirrored in both `.sh` hooks.
- **L1 `skill_vetting` — robustness.** A valid-JSON but non-dict `package.json` no longer raises (the "never raises" contract holds); a file over the size cap now emits an `UNSCANNED` finding and floors the tier away from `approved` (padded-past-the-cap malware can no longer score 0 → approved).
- **L2 `sanitize` — bounded NFKC.** NFKC now runs in combining-safe chunks with a cumulative-output budget and a pathological-expansion circuit breaker, so a compatibility expander no longer stalls the sanitizer; benign input of any length is still fully normalized, and the NFKC and scan budgets are aligned so there is no partial-fold evasion gap.
- **L6 `audit` — anchoring honesty.** Documented the unanchored-tail blind spot (periodic anchoring leaves the window since the last anchor forgeable) with a regression test pinning that `verify()` is tamper-*evident*, not tamper-resistant. Corrected the "imports no networking library" claim — the package imports `socket` only for `gethostname()` and makes no outbound calls.
- **Privacy.** Test docstrings anonymized.
- **Docs.** README intro states the six shipping layers; `pyproject` / `__init__` descriptions aligned; version coherence to `0.1.0a4`.

### Layer 7 — Configuration (added 2026-06-15)
- **`agent_shield/config.py`** — the cross-layer configuration spine + shared compliance contract. `config.load(path=None, *, compliance=…, audit_path=…, sanitize_strict=…, structured_output_mode=…) → Config`, plus frozen `Config` / `AuditConfig` / `SanitizeConfig` / `StructuredOutputConfig` / `GuardConfig` (each with `to_dict()`) and `config.preset_names()`. Stdlib-only, zero runtime dependencies.
- **`load()` never raises into a caller** — missing / malformed / wrong-type / oversized (> 1 MiB) / non-regular / unknown-preset / non-UTF-8 / duplicate-key / BOM all degrade to built-in defaults + a surfaced `UserWarning`. A layer always runs with zero config present.
- **Preset parity, single-sourced** — compliance presets mirror `audit.PRESETS` exactly (`general` / `healthcare` / `biotech`) by importing that table, so they can't drift; an unknown/typo'd value falls back to `general` + a warning and can never reach `AuditLog`. There is no `enterprise` preset in v0.1; `audit.retention_days` / `fail_mode` / `content_fields_always` are preset-derived, read-only reported values.
- **Precedence** — built-in defaults < config file < environment < explicit kwargs, resolved per field; a present-but-invalid value warns and falls through to the next-lower tier. An override that downgrades a preset (e.g. `sanitize.strict=false` under `healthcare`) is surfaced as a warning, never silent.
- **Not a trust boundary** — config carries policy/paths, never secrets, and cannot weaken a built-in guard (no `extra_red` / `extra_yellow` keys in v0.1). Opt-in wiring only: the guards do not auto-load config; callers pass slices explicitly.
- **Cross-layer (Layer 4)** — the config file is a `write_guard` YELLOW target (`agent-shield.toml`, `~/.agent-shield/config.toml`), mirrored in the bash port. **TOML only** — YAML is rejected (third-party dependency + `yaml.load` code-exec footgun).
- **`docs/CONFIGURATION.md`** + README "8 layers" table + Project Status flip Layer 7 🟡→✅ (now "Layers 1, 2, 3, 4, 6, and 7 ship").
- Hardened via an independent adversarial review pass (verifiers read-only). Key correctness fix: `load()` is now total even under a caller-imposed warnings-as-errors filter (`python -W error`).

### Layer 3 — Structured Output (added 2026-06-15)
- **`agent_shield/structured_output.py`** — a stdlib schema validator that constrains agent/tool output to a declared structure and rejects what doesn't conform (reducing the blast radius of "make the agent emit free-form X"). `Schema(spec)`, `Field(spec, **constraints)`, `enforce(output, schema, *, mode) → EnforceResult(ok, value, errors)`, plus `expect_json(text)` / `extract_json(text)`. Stdlib-only; never-crash on any output / malformed JSON / huge or deeply-nested input; deterministic; **never executes, evals, or decodes** the payload.
- **Shape, not intent** — enforces the *structure* of a tool call/response; a well-formed object whose values are malicious still passes. Defense-in-depth, **not** a prompt-injection blocker.
- **Schema DSL** — bare types, nested `Schema`, `list[T]`, `dict[str, T]`, `Union`/`Optional`, `Literal`, `(type, default)` optionals, and `Field(...)` constraints (`min_len`/`max_len`/`ge`/`le`/`pattern`/`choices`). A malformed spec raises at construction; `enforce()` against any runtime payload never raises.
- **Exact-identity type matching** — an `int` field rejects `True`/`False`, a `bool` field rejects `0`/`1`; `int` widens to `float` (JSON has no `1` vs `1.0`); `NaN`/`Infinity` are rejected.
- **Collect-all, deterministic, path-qualified errors** (e.g. `$.args[2].name: expected string, got integer`) in schema-declared order. **strict** rejects unexpected keys, **lenient** drops them; absent `(type, default)` optionals are filled in; `value` is a fresh non-aliased dict on success and `None` on failure; `enforce` never mutates its input.
- **Bounded JSON-discipline helpers** via `json.JSONDecoder().raw_decode` (no regex on the payload). `expect_json` accepts only a single bare object; `extract_json` is bounded by length / attempt / depth caps.
- **Deferred to v0.2:** canary tokens (need a response-stream hook) and optional pydantic interop. v0.1 imports no third-party package.
- **`docs/STRUCTURED_OUTPUT.md`** + README "8 layers" table + Project Status flip Layer 3 🟡→✅.
- Hardened via two independent adversarial review rounds (each finding repro-verified before fixing).

### Layer 2 — Input Sanitization (added 2026-06-15)
- **`agent_shield/sanitize.py`** — heuristic sanitization of untrusted incoming content (web fetches, tool/MCP output, user input, agent-to-agent handoffs) before it reaches the model. `sanitize.sanitize(text, source=…, strict=…) → SanitizeReport` + `sanitize.clean(text) → str`. Stdlib-only; never-crash on any input (incl. invalid Unicode / lone surrogates / multi-MB); deterministic; the cleaned text is idempotent.
- **Four sub-layers, pipeline-ordered** — **encoding** (NFKC-normalize first, then *detect* — never decode — long base64/base64url blobs and mixed-script homoglyph tokens); **structural** (strip zero-width/BOM, BIDI overrides + isolates + directional marks, Unicode tag chars, C0/C1 controls except `\t\n\r`, lone surrogates; ZWJ/ZWNJ preserved); **content** (detect-and-flag injection/jailbreak markers, non-destructive by default with opt-in `strict=True` neutralization); **context** (nonce-delimited typed wrappers).
- **Detection ≠ prevention** — strips invisible/control chars (destructive, safe) and flags markers/encodings (non-destructive by default); it does **not** block prompt injection — novel phrasings and encodings are unbounded. A flag is a "look here," not a verdict.
- **Nonce-delimited wrappers** — `wrap_web` / `wrap_user_input` / `wrap_agent_output` / `wrap_tool_output` (each cleans first, then wraps). A fresh 128-bit CSPRNG nonce in both the open and close tag is the breakout defense; the contract that the consuming prompt must honor the delimiters is the integrator's job, documented as such.
- **Anti-ReDoS by construction** — every marker/encoding pattern is flat and bounded (no nested quantifiers), pre-compiled at import; an oversize-input cap bounds the deep scan and emits an `oversize_unscanned` finding.
- **`docs/SANITIZATION.md`** + README "8 layers" table + Project Status flip Layer 2 🟡→✅.
- Hardened via two independent adversarial review rounds (each finding re-verified by repro before fixing).

### Layer 6 — Structured Audit (added 2026-06-14)
- **`agent_shield/audit.py`** — append-only, tamper-evident JSON-Lines audit log. A 9-field base schema + SHA-256 content hashes for write events (`record_write`) + a per-entry hash chain (`seq` / `prev_hash` / `entry_hash`) that `verify()` validates and that detects edits / insertions / deletions / reorders. `AuditLog.record` / `record_write` / `verify` + CLI (`python -m agent_shield.audit --verify <path>`, exit 0/1/2 = intact/tampered/unreadable). Stdlib-only.
- **Fail-open by default** — a logging failure prints a stderr warning and returns `None`; it never raises into the operation being audited. Presets: `general` (9-field, 90-day, fail-open) and `healthcare`/`biotech` (uniform 11-field, 365-day, fail-closed — "no action without an audit record"); opt in with `fail_mode="closed"`.
- **Tier-1 external anchor (`audit.Anchor`)** — optional, opt-in, off by default. Periodically (every N entries or T minutes — never per-event) ships a minimal head receipt `{seq, entry_hash, ts}` (no PII) to a local protected path or a user-supplied shipper, upgrading the chain from tamper-EVIDENT to tamper-RESISTANT when the target is independent. Fail-open even under the fail-closed preset.
- **"never phones home"** — the package ships no networking code; the built-in anchor writes only to the local filesystem, and remote anchoring is achieved solely by a user-supplied shipper (their code, their egress). There is no `url`/`endpoint` parameter. Enforced by an AST scan in the suite (a best-effort lint, not a sandbox).
- **`docs/AUDIT_SCHEMA.md`** — field reference, canonical-serialization spec, verification procedure, compliance presets, the anchoring model, and an honest threat model (tamper-evident always / not tamper-proof ever / tamper-resistant only when anchored to an independent target).
- **`examples/remote_anchor_shipper.py`** + **`docs/REMOTE_ANCHORING.md`** — an opt-in bring-your-own-shipper recipe + risk guide. The package still ships no network code; remote egress is the user's own transport, documented with its risks.
- README "8 layers" table + Project Status flip Layer 6 🟡→✅.
- Hardened via an independent adversarial review pass (each finding re-verified before fixing).

### Fixed (2026-06-12 — pre-push review)
- **Version coherence.** `__version__` now reads from installed package metadata (single source = `pyproject.toml`), the README badge and `INSTALL_AGENT.md` reference the current alpha throughout, and the withdrawn-wheel install line was replaced with a build-from-source note.
- **INSPIRATIONS.md** dead cross-reference removed; internal agent codenames in the umbrella `_oss-templates/INSPIRATIONS.md` anonymized to match the shipped packages.

### Changed (2026-06-11 — private-key tier split)
- `*.pem` / `*.key` moved from RED (hard-deny) to **YELLOW (ask)**. The extension match is content-blind — `fullchain.pem` is a *public* certificate and `.key` is also Apple Keynote's document type — so a hard block was a false positive on ordinary files. SSH private keys (`~/.ssh/id_*`) and `.openclaw/.env`, which are *unambiguously* secret, stay RED. A real private key in a `.pem`/`.key` file is still protected (the agent must stop and ask before overwriting it).

### Added (2026-06-12 — Layer 1: Skill / Tool Vetting)
- **`agent_shield/skill_vetting.py`** — a static, **read-only** supply-chain vetter. Scans a skill / MCP server / hook / package, scores it 0–10, and returns a 3-tier verdict (**approved / review / rejected**) with structured findings. `skill_vetting.vet_path(path) → VetResult` + CLI (`python -m agent_shield.skill_vetting <path>`, exit 0/1/2; console script `agent-shield-vet`). Threat categories: `ENV_BULK`, `ENV_SCRAPE`, `CRED_PATH`, `FS_DANGER`, `PIPE_TO_SHELL`, `PERSIST`, `NET_EXFIL`, `CRYPTO_MINE`, `PROMPT_INJECTION`, `TYPOSQUAT`. Read-only (never executes / imports / writes / fetches the target), zero runtime dependencies, never crashes on missing/binary/malformed input, and never silently approves something it could not scan.
- **`docs/VETTING_ESCALATION.md`** — the 5-layer manual escalation rubric for the review tier.
- README "8 layers" table + Project Status flip Layer 1 🟡→✅.

### Security (2026-06-11 — additional hardening)
- **Self-protection normalization generalized.** `_normalize_path` peels an `X:` drive prefix, strips any ADS stream from the final segment, and strips trailing whitespace + dots — closing single-colon ADS (`file.py:stream`, `file.py:$DATA`), trailing-tab, and other whitespace bypasses of the `$`-anchored RED patterns. Mirrored in the bash source.
- **ReDoS fixed.** The decode-and-execute and `Remove-Item -Recurse -Force` patterns no longer use unbounded/nested `.*` (≈ 9 s and ≈ 37 s on large adversarial input); decode-exec gaps are bounded and Remove-Item uses linear lookaheads. Linear-time regression tests added.
- **Multi-line command-position bypass + py↔bash divergence fixed.** A shared command-start prefix used with `re.MULTILINE` (parity with the per-line bash `grep`) closes the non-first-line bypass and the `FOO=1 verb` env-var-prefix evasion in both ports.

### Security (2026-06-11 — pre-launch hardening)
- **Self-protection bypass fixed (write_guard).** Path normalization strips NTFS alternate-data-stream suffixes (`file.py::$DATA`) and trailing spaces/dots before matching. Mirrored in the bash source.
- **CLI fail-open crash fixed (both guards).** Malformed hook stdin no longer raises into an unevaluated pass; extractors are total and `main()` enforces the always-exit-0 contract.
- **ReDoS fixed (bash_guard).** The credential-exfil regex's unbounded `.*` gaps are replaced with a staged linear search with identical per-line semantics.
- **Encoding fail-open fixed (both guards).** UTF-8-BOM and UTF-16 stdin are BOM-sniffed and decoded defensively; RED commands in UTF-16 input are evaluated and denied.
- **Bash interpreter validation (both bash sources).** Candidate interpreters are executed, not just `command -v`'d (so a non-working `python3` alias can't silently empty extraction); the `py` launcher is added as a fallback.
- **No-Python fail-closed (bash_guard source).** When no working Python exists, RED checks also scan the raw hook JSON, so sed-fallback truncation can no longer hide credential exfiltration.
- **New RED protections:** private keys (`*.pem` / `*.key`, `~/.ssh/id_*`) and `.openclaw/.env`; quoted / split-flag / home / cwd `rm -rf` variants; decode-and-execute (`base64 -d | sh`); process substitution (`bash <(curl …)`); credential-FILE exfiltration; `format X:` / `wipefs`.
- **New YELLOW protections:** shell startup files (persistence vector); Windows-native recursive deletes (`del /s`, `Remove-Item -Recurse -Force`); `shred`; split-flag `rm -r -f` off-root.
- **False-positive fix:** destructive-verb patterns (`mkfs`, `dd`, `format`) are anchored to command position, so `grep mkfs log` and `dd … of=/dev/null` no longer deny.

### Added (2026-06-12 — packaging + docs)
- `INSTALL_AGENT.md` — an agent-executed install: a consent-gated flow covering Python-environment detection, package install, hooks wiring (never edits harness settings without showing the diff), contract smoke verification, and an optional install manifest.
- Cross-platform equivalence test runner (`tests/run_equivalence_test.py`) — runs the same case matrix against both the Python port and the bash sources and asserts decision-equivalence.
- Apache-2.0 LICENSE + NOTICE + AUTHORS + CONTRIBUTING + CLA + INSPIRATIONS at the package root.
- A public README (install / 8-layer overview / Layer 4 detail / library + CLI API / Claude Code hook wiring / tier model / security model).
- `write_guard` self-protection extended to `agent_shield/*.py`; the credential-exfil regex catches both `$VAR` and `${VAR}` forms.

### Changed (2026-06-11)
- **README rewritten for doc-code truth** — real pattern counts, the fabricated "GREEN patterns" lists removed (GREEN is the default tier, not an allowlist), "byte-equivalent" softened to the verified "decision-equivalent", and a frank **Bypasses & limitations** section added. Counts and headline protections are verified by automated tests — README drift fails the suite.
- `SECURITY.md` reporting channel corrected to GitHub private vulnerability reporting.
- pyproject classifier honesty: `Development Status :: 3 - Alpha`; `py.typed` marker added (PEP 561); a standalone `CODE_OF_CONDUCT.md` added and linked from CONTRIBUTING.
- Package description sharpened; license declared explicitly as Apache-2.0 in `pyproject.toml` + every source file.

---

## [0.1.0a2] — 2026-06-10 — alpha 2 (renumbered for PEP-440 compliance)

The pre-publish alpha of the Python port. No functional changes vs the prior artifact; metadata + version-string compliance + the self-protection / credential-exfil follow-on patches.

### Layer 4 — Runtime Hooks (shipping)
- `agent_shield/bash_guard.py` — RED + YELLOW pattern tiers with a GREEN default.
- `agent_shield/write_guard.py` — RED + YELLOW pattern tiers with a GREEN default.
- `agent_shield/_result.py` — `GuardResult` dataclass with `to_hook_json()` for Claude Code PreToolUse compatibility.
- CLI entries: `agent-shield-bash-guard` + `agent-shield-write-guard`.
- Zero runtime dependencies; Python ≥ 3.12 required.

---

## How releases are numbered

- `0.x.y` — alpha / pre-1.0; APIs may change between minor versions.
- `0.1.0a1` / `0.1.0a2` / `0.1.0b1` / `0.1.0rc1` — alpha / beta / release-candidate progressions toward `0.1.0`.
- `1.0.0` — first stable release with API guarantees.

The version is bumped on every public push; pre-release suffixes (`aN`, `bN`, `rcN`) signal stability tier per PEP-440.

---

*Maintained by `esoteric1entity`. A PDuk Brainworks project — sibling to [Ultimate Memory Stack](https://github.com/esoteric1entity/ultimate-memory-stack) under [The Agent Architect Stack](https://github.com/esoteric1entity/agent-architect-stack).*
