# Layer 7 — Configuration (`agent_shield.config`)

> **Policy, not a trust boundary.** Configuration declares *what posture you
> want* — a compliance preset, an audit path, sanitizer strictness — in one
> place, so the layers stop hard-coding it. It is **not** a security control on
> its own: an attacker who can edit the config file can only *weaken* policy, so
> the config file itself is a `write_guard` **YELLOW** target (Layer 4), and the
> loader can **never remove or relax a built-in guard pattern**. Config holds
> **paths and policy, never secrets.**

Stdlib-only (`tomllib`, `os`, `pathlib`, `dataclasses`, `warnings`) · **TOML**
(read-only; you edit the file, agent-shield only reads it) · **never-crash** —
any missing / malformed / mistyped / oversized / unknown-preset input degrades
to built-in defaults with a surfaced `UserWarning`, so a layer always runs.
Apache-2.0.

```python
from agent_shield import config

cfg = config.load()                 # search-path + defaults; NEVER raises
cfg.compliance                      # "general" | "healthcare" | "biotech"
cfg.audit.path                      # str (a leading ~ is expanded)
cfg.audit.retention_days            # int  — preset-DERIVED (read-only)
cfg.audit.fail_mode                 # "open" | "closed" — preset-derived (read-only)
cfg.sanitize.strict                 # bool
cfg.structured_output.mode          # "strict" | "lenient"
```

## Opt-in wiring (v0.1)

The guards do **not** auto-load config — they take no hot-path file I/O and stay
exactly as reviewed. Callers pass the slice they need:

```python
from agent_shield import config, audit

cfg = config.load()
log = audit.AuditLog(path=cfg.audit.path, preset=cfg.compliance)   # explicit
```

`Config` reflects the **declared** policy as resolved by `load()`. An explicit
keyword passed *directly* to a layer constructor wins at that layer and is **not**
reflected back into `Config` — so pass the slice rather than mixing config and
ad-hoc kwargs.

## The shared contract (`Decision` / `GuardResult`)

The spine also includes the common result type the runtime guards agree on,
re-exported at the package root as `GuardResult`:

```python
from agent_shield import GuardResult        # re-exported at the package root
Decision = "allow" | "ask" | "deny"          # a Literal type alias
GuardResult(decision, reason="").to_hook_json()   # -> Claude Code PreToolUse JSON, or None for "allow"
```

The **Layer-4 guards** (`bash_guard.check_command`, `write_guard.check_path`)
return a `GuardResult`. Other layers return their own typed results (audit's
verification result, structured-output's enforce result, skill-vetting's verdict);
`GuardResult`/`Decision` is the shared piece, not a universal return type.

---

## The config file — `agent-shield.toml`

```toml
compliance = "general"          # one of: general | healthcare | biotech

[audit]
path = "~/.agent-shield/audit.jsonl"

[sanitize]
strict = false

[structured_output]
mode = "strict"                 # strict | lenient
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `compliance` | str | `general` | Validated against `audit.PRESETS`; an unknown/typo'd value falls back to `general` + a warning (it can never reach `AuditLog`, which raises on an unknown preset). |
| `audit.path` | str | `~/.agent-shield/audit.jsonl` | A leading `~` is expanded; a non-string is rejected (default kept). |
| `sanitize.strict` | bool | preset-derived | `false` for `general`; `true` for `healthcare`/`biotech`. Must be a real TOML bool — a quoted `"false"` is a mistype (rejected, default kept), so a string can never silently flip strictness. |
| `structured_output.mode` | str | `strict` | Validated against `structured_output.MODES` (`strict`/`lenient`). |

`audit.retention_days`, `audit.fail_mode`, and `audit.content_fields_always` are
**derived from the compliance preset and reported read-only** — there is no
writable override for them in v0.1 (the audit layer has no such constructor
argument; see *Deferred to v0.2*).

Unknown keys and unknown tables are **ignored** (no crash). In particular there
are **no `extra_red` / `extra_yellow` keys** in v0.1 — a config that could append
to, let alone remove from, a guard's pattern tiers is a policy-weakening surface
and is deferred to v0.2 with its own review.

---

## Compliance presets

The preset names mirror `agent_shield.audit.PRESETS` **exactly** — config
single-sources that table rather than re-declaring it, so the two can never drift.

| Preset | audit retention | audit fail mode | audit rows | sanitize.strict |
|---|---|---|---|---|
| `general` | 90 days | `open` | 9-field | `false` |
| `healthcare` | 365 days | `closed` | 11-field (content SHA-256) | `true` |
| `biotech` | 365 days | `closed` | 11-field (content SHA-256) | `true` |

`biotech` is semantically identical to `healthcare` today. There is **no
`enterprise` preset** in v0.1: it has no backing in the audit layer and would
crash `AuditLog`. An `enterprise` tier, if added, must land in `audit.PRESETS`
first (with concrete retention / fail-mode / content semantics and a pinning
test), then surface here.

---

## Search path & precedence

`load(path=None, *, compliance=None, audit_path=None, sanitize_strict=None, structured_output_mode=None)`

**File search** (first existing path wins):

1. an explicit `path=` argument
2. `$AGENT_SHIELD_CONFIG` (empty / whitespace-only is treated as unset)
3. `./agent-shield.toml` (current working directory)
4. `~/.agent-shield/config.toml`

A missing *explicit* path (arg or env) warns; missing *default-search* legs are
silent. A file that exists but is unusable (a directory or other non-regular
file, larger than 1 MiB / `MAX_CONFIG_BYTES`, unreadable, or malformed TOML)
warns and yields built-in defaults for the **whole** file (TOML is all-or-nothing
— one stray duplicate key discards the entire file).

**Value precedence** (per field, low → high):

> built-in defaults  <  config file  <  environment  <  explicit keyword arguments

A present-but-invalid value at one tier warns and falls through to the next-lower
tier. If an explicit `sanitize.strict=false` override weakens a preset that
defaults it **on** (`healthcare`/`biotech`), that specific weakening is surfaced
as a warning. Changing `compliance` itself between tiers (e.g. an env var
overriding a file's `healthcare` with `general`) is normal precedence and is
**not** warned — it is the operator's explicit choice of posture.

### Environment variables

Settings (distinct from the `AGENT_SHIELD_CONFIG` *path* variable):

| Variable | Sets |
|---|---|
| `AGENT_SHIELD_CONFIG` | the config *file* location (search leg 2) |
| `AGENT_SHIELD_COMPLIANCE` | `compliance` |
| `AGENT_SHIELD_AUDIT_PATH` | `audit.path` |
| `AGENT_SHIELD_SANITIZE_STRICT` | `sanitize.strict` (truthy `1/true/yes/on`, falsy `0/false/no/off`, case-insensitive; anything else is ignored + warned) |
| `AGENT_SHIELD_STRUCTURED_OUTPUT_MODE` | `structured_output.mode` |

`AGENT_SHIELD_ACTOR`, `AGENT_SHIELD_ROLE`, `AGENT_SHIELD_SESSION`, and
`AGENT_SHIELD_MACHINE` are **audit runtime fields, not config keys** — config
deliberately does not own them, so each env name has exactly one reader.

---

## Bypasses & limitations

- **Not a trust boundary.** Config carries policy and paths only. An attacker who
  can edit it can weaken posture (that is why the config file is a `write_guard`
  YELLOW target) — it cannot strengthen security on its own.
- **The config file cannot weaken a built-in guard.** In v0.1 the guards do not
  read config; their RED/YELLOW pattern tiers are hard-coded. No config input can
  drop a built-in RED command below `deny`.
- **A non-default `$AGENT_SHIELD_CONFIG` location is not guarded.** `write_guard`
  protects the two well-known config locations (the basename `agent-shield.toml`
  and the path `~/.agent-shield/config.toml`); a static path matcher cannot know
  an arbitrary env-pointed location, so protecting it is the operator's
  responsibility.
- **No secrets.** Do not put tokens or credentials in the config; it is plaintext
  policy. Credentials belong in the environment / a secrets manager.
- **TOML only.** YAML is intentionally **rejected** (it would add a third-party
  dependency and `yaml.load` is a code-execution footgun); JSON is not a v0.1
  input either. The file is TOML, read with the stdlib `tomllib`.

---

## Deferred to v0.2 (documented, not built)

- `extra_red` / `extra_yellow` (and any user-supplied guard patterns) — needs its
  own pre-mortem (regex-compile failure handling, a ReDoS / length budget, and
  strictly add-only / tighten-only semantics — never remove a built-in).
- Auto-wiring the layers to self-load config (the no-I/O-in-guards invariant must
  be re-decided first).
- An `enterprise` compliance tier (must land in `audit.PRESETS` first).
- A writable `retention_days` / `fail_mode` override into the audit layer (needs a
  new `AuditLog` constructor argument — a guard-API change with its own review).
- Live config reload / file-watching; a config-writing API; multi-file merge /
  include directives. (Load-at-start only; `tomllib` is read-only by design.)
