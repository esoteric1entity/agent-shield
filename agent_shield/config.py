"""config — agent-shield Layer 7 (Configuration + the shared compliance contract).

The cross-layer spine: one place to declare a threat model / compliance preset
once, and the typed slices each layer consumes.

    from agent_shield import config
    cfg = config.load()                       # search-path + defaults, NEVER raises
    cfg.compliance                            # "general" | "healthcare" | "biotech"
    cfg.audit.path, cfg.audit.retention_days  # retention/fail_mode are preset-DERIVED (read-only)
    cfg.sanitize.strict                       # bool
    cfg.structured_output.mode                # "strict" | "lenient"

    # opt-in wiring (v0.1): callers pass slices explicitly; the guards do NOT
    # auto-load config (no hot-path file I/O, no eager import).
    from agent_shield import audit
    log = audit.AuditLog(path=cfg.audit.path, preset=cfg.compliance)

Hard guarantees:
  - **Total.** ``load()`` never raises into a caller — missing file -> built-in
    defaults; malformed / wrong-type / oversized / non-regular / unknown-preset
    -> built-in defaults + a surfaced ``UserWarning``. A layer runs with zero config.
  - **Preset parity.** Compliance presets mirror ``audit.PRESETS`` EXACTLY
    (general / healthcare / biotech), single-sourced by importing that table —
    an unknown/typo'd preset can never reach ``AuditLog`` (which raises ``ValueError``).
  - **Precedence.** built-in defaults < config file < environment < explicit kwargs.
  - **Not a trust boundary.** Config carries policy/paths, never secrets, and
    cannot remove or relax a built-in guard pattern (no pattern-injection keys
    ship in v0.1). The config file itself is a ``write_guard`` YELLOW candidate.

Stdlib-only; ``tomllib`` is unconditionally available on the package's >=3.11
floor (read-only — users edit the file, we only read it, in BINARY mode).

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import os
import tomllib
import warnings
from dataclasses import dataclass, field
from pathlib import Path

# =============================================================================
# Constants (also the pinned doc-contract — see docs/CONFIGURATION.md)
# =============================================================================
DEFAULT_COMPLIANCE = "general"
DEFAULT_MODE = "strict"
DEFAULT_AUDIT_PATH = "~/.agent-shield/audit.jsonl"

#: A policy file is kilobytes; anything larger is rejected fast (local-DoS guard).
MAX_CONFIG_BYTES = 1_048_576  # 1 MiB

#: Env var naming the config FILE location (highest-priority search leg after an
#: explicit ``path=`` arg). Empty / whitespace-only is treated as unset.
CONFIG_PATH_ENV = "AGENT_SHIELD_CONFIG"

#: The finite, documented set of env-overridable SETTINGS, ``AGENT_SHIELD_<SECTION>_<KEY>``.
#: Note: ``AGENT_SHIELD_{ACTOR,ROLE,SESSION,MACHINE}`` are AUDIT-runtime fields,
#: NOT config keys — config deliberately does not own them (one reader per name).
ENV_KEYS = {
    "AGENT_SHIELD_COMPLIANCE": "compliance",
    "AGENT_SHIELD_AUDIT_PATH": "audit.path",
    "AGENT_SHIELD_SANITIZE_STRICT": "sanitize.strict",
    "AGENT_SHIELD_STRUCTURED_OUTPUT_MODE": "structured_output.mode",
}

#: Compliance tiers that tighten input sanitization by default. A subset of the
#: audit preset names (pinned by test); an unlisted preset defaults to non-strict.
STRICT_SANITIZE_COMPLIANCE = frozenset({"healthcare", "biotech"})

_TRUE_TOKENS = frozenset({"1", "true", "yes", "on"})
_FALSE_TOKENS = frozenset({"0", "false", "no", "off"})


# =============================================================================
# Data shapes — frozen, with to_dict() (house style)
# =============================================================================
@dataclass(frozen=True)
class AuditConfig:
    """Audit-layer slice. ``retention_days`` / ``fail_mode`` / ``content_fields_always``
    are DERIVED from the compliance preset (read-only reported values in v0.1)."""

    path: str = DEFAULT_AUDIT_PATH
    retention_days: int = 90
    fail_mode: str = "open"
    content_fields_always: bool = False

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "retention_days": self.retention_days,
            "fail_mode": self.fail_mode,
            "content_fields_always": self.content_fields_always,
        }


@dataclass(frozen=True)
class SanitizeConfig:
    """Input-sanitization slice."""

    strict: bool = False

    def to_dict(self) -> dict:
        return {"strict": self.strict}


@dataclass(frozen=True)
class StructuredOutputConfig:
    """Structured-output slice; ``mode`` is validated against ``structured_output.MODES``."""

    mode: str = DEFAULT_MODE

    def to_dict(self) -> dict:
        return {"mode": self.mode}


@dataclass(frozen=True)
class GuardConfig:
    """Runtime-guard slice. Intentionally EMPTY in v0.1 — pattern add-ons
    (``extra_red`` / ``extra_yellow``) are deferred to v0.2 with their own
    pre-mortem, because a config that can remove/relax a built-in pattern would
    be a policy-weakening downgrade in a security tool."""

    def to_dict(self) -> dict:
        return {}


@dataclass(frozen=True)
class Config:
    """The resolved, frozen configuration. Reflects DECLARED policy as resolved
    by ``load()`` (defaults < file < env < kwargs). An explicit kwarg passed
    directly to a layer constructor wins at that layer and is NOT reflected here."""

    compliance: str = DEFAULT_COMPLIANCE
    audit: AuditConfig = field(default_factory=AuditConfig)
    sanitize: SanitizeConfig = field(default_factory=SanitizeConfig)
    structured_output: StructuredOutputConfig = field(default_factory=StructuredOutputConfig)
    guard: GuardConfig = field(default_factory=GuardConfig)

    def to_dict(self) -> dict:
        return {
            "compliance": self.compliance,
            "audit": self.audit.to_dict(),
            "sanitize": self.sanitize.to_dict(),
            "structured_output": self.structured_output.to_dict(),
            "guard": self.guard.to_dict(),
        }


# =============================================================================
# Lazy single-source imports (respect __init__'s no-eager-import rule; no cycle)
# =============================================================================
def _audit_presets() -> dict:
    from agent_shield import audit  # lazy: never at module top

    return audit.PRESETS


def _modes() -> tuple:
    from agent_shield import structured_output  # lazy

    return structured_output.MODES


def preset_names() -> tuple:
    """The compliance preset names config accepts — exactly ``audit.PRESETS`` keys."""
    return tuple(sorted(_audit_presets()))


# =============================================================================
# Warnings — always UserWarning (never DeprecationWarning, which the suite errors on)
# =============================================================================
def _warn(msg: str) -> None:
    # The sole warning chokepoint. Guarded so a caller who promotes warnings to
    # errors (`python -W error`, an app-level simplefilter('error'), or pytest
    # filterwarnings=error) can NEVER turn a degrade-path warning into a raise —
    # that would break load()'s never-raise contract on exactly the malformed
    # inputs it exists to absorb. Every degrade path (inner resolver + the outer
    # except handler) routes through here, so this one guard closes both sites.
    try:
        warnings.warn(msg, UserWarning, stacklevel=2)
    except Exception:  # noqa: BLE001 — a caller's -W error must not violate totality
        pass


# =============================================================================
# Coercion helpers — total: each returns (ok, value); ok=False means "ignore this
# tier" (the resolver warns and falls through to the next-lower tier).
# =============================================================================
def _str_in(valid):
    """Factory: accept a str that is a member of ``valid`` (exact, case-sensitive)."""

    def coerce(raw):
        if isinstance(raw, str) and raw in valid:
            return True, raw
        return False, None

    return coerce


def _coerce_path(raw):
    """Accept a non-empty str path; strip surrounding whitespace, then expand a
    leading ``~`` (strip-first so the tilde is at index 0 and actually expands —
    all tiers agree with the env tier and the documented "leading ~ is expanded")."""
    if isinstance(raw, str) and raw.strip():
        return True, _expand(raw.strip())
    return False, None


def _bool_from_native(raw):
    """File tier: require a real TOML bool. A string/int is a MISTYPE (rejected),
    so e.g. ``strict = "false"`` can never silently flip a preset's strictness."""
    if isinstance(raw, bool):
        return True, raw
    return False, None


def _bool_from_str(raw):
    """Env tier: values are always strings — parse a fixed truthy/falsy token set."""
    if isinstance(raw, str):
        tok = raw.strip().lower()
        if tok in _TRUE_TOKENS:
            return True, True
        if tok in _FALSE_TOKENS:
            return True, False
    return False, None


def _bool_lenient(raw):
    """Kwarg tier: accept a native bool, or a parseable string."""
    if isinstance(raw, bool):
        return True, raw
    if isinstance(raw, str):
        return _bool_from_str(raw)
    return False, None


def _expand(path_str: str) -> str:
    try:
        return os.path.expanduser(path_str)
    except Exception:  # noqa: BLE001 — never let path expansion crash load()
        return path_str


def _env_setting(name: str):
    """Read a setting env var, normalized: surrounding whitespace stripped and an
    empty/whitespace-only value treated as **unset** (None) — mirroring how
    ``$AGENT_SHIELD_CONFIG`` is handled, so an exported-but-empty var is silently
    ignored (not a spurious warning) and a stray trailing space on an enum value
    (e.g. ``AGENT_SHIELD_COMPLIANCE=healthcare ``) doesn't silently downgrade it."""
    v = os.environ.get(name)
    if v is None:
        return None
    v = v.strip()
    return v or None


# =============================================================================
# Tier resolution
# =============================================================================
def _resolve(field_name, default, tiers):
    """Walk ``tiers`` (high->low precedence: each is (name, raw, coercer)); return
    (value, source_tier). A present-but-invalid value warns and falls through."""
    for name, raw, coerce in tiers:
        if raw is None:
            continue
        ok, val = coerce(raw)
        if ok:
            return val, name
        _warn(
            f"agent-shield config: ignoring invalid {field_name} from {name} "
            f"({raw!r}); falling back to the next source"
        )
    return default, "default"


# =============================================================================
# File layer — total: returns the parsed dict, or {} on any unusable file.
# =============================================================================
def _safe_home():
    try:
        h = os.path.expanduser("~")
        if not h or h == "~":  # could not expand (HOME/USERPROFILE unset)
            return None
        return h
    except Exception:  # noqa: BLE001
        return None


def _candidate_specs(explicit_path):
    """Ordered search: explicit arg -> $AGENT_SHIELD_CONFIG -> ./agent-shield.toml
    -> ~/.agent-shield/config.toml. Each is (path_str, is_explicit)."""
    specs = []
    if explicit_path is not None:
        specs.append((os.fspath(explicit_path), True))
    env_path = os.environ.get(CONFIG_PATH_ENV)
    if env_path and env_path.strip():
        specs.append((env_path.strip(), True))
    specs.append(("agent-shield.toml", False))  # cwd-relative
    home = _safe_home()
    if home is not None:
        specs.append((os.path.join(home, ".agent-shield", "config.toml"), False))
    return specs


def _read_file_layer(explicit_path):
    """Find and parse the first existing config file. Missing default-search legs
    are silent; a missing EXPLICIT path warns. A found-but-unusable file (non-
    regular / oversized / unreadable / malformed) warns and yields built-in
    defaults for the WHOLE file (TOML is all-or-nothing)."""
    for path_str, is_explicit in _candidate_specs(explicit_path):
        try:
            p = Path(path_str)
            if not p.exists():
                if is_explicit:
                    _warn(f"agent-shield config: path not found: {path_str!r}; using built-in defaults")
                continue
            if not p.is_file():
                _warn(f"agent-shield config: not a regular file: {path_str!r}; using built-in defaults")
                return {}
            size = p.stat().st_size
            if size > MAX_CONFIG_BYTES:
                _warn(
                    f"agent-shield config: file too large ({size} bytes > "
                    f"{MAX_CONFIG_BYTES}): {path_str!r}; using built-in defaults"
                )
                return {}
            with open(p, "rb") as fh:  # BINARY — tomllib.load requires it; BOM-correct
                data = tomllib.load(fh)
            if not isinstance(data, dict):
                _warn(f"agent-shield config: top-level is not a table: {path_str!r}; using built-in defaults")
                return {}
            return data
        except FileNotFoundError:
            if is_explicit:
                _warn(f"agent-shield config: path not found: {path_str!r}; using built-in defaults")
            continue
        except tomllib.TOMLDecodeError as e:  # subclass of ValueError — must precede it
            _warn(
                f"agent-shield config: malformed TOML in {path_str!r} ({e}); "
                f"falling back to built-in defaults for the entire file"
            )
            return {}
        except (OSError, UnicodeDecodeError, ValueError) as e:
            _warn(f"agent-shield config: cannot read {path_str!r} ({e}); using built-in defaults")
            return {}
    return {}


def _subtable(d, key):
    """Return ``d[key]`` if it is a table, else {} (warning if present-but-not-a-table)."""
    val = d.get(key)
    if val is None:
        return {}
    if isinstance(val, dict):
        return val
    _warn(f"agent-shield config: [{key}] is not a table ({val!r}); ignoring it")
    return {}


# =============================================================================
# Public loader
# =============================================================================
def load(
    path=None,
    *,
    compliance=None,
    audit_path=None,
    sanitize_strict=None,
    structured_output_mode=None,
):
    """Load configuration. **Total — never raises into a caller** for any input.

    Args:
        path: explicit config-file path (highest-priority search leg).
        compliance / audit_path / sanitize_strict / structured_output_mode:
            explicit per-field overrides (highest precedence of all tiers).

    Returns:
        A frozen :class:`Config`. Invalid/missing inputs degrade to built-in
        defaults with a surfaced ``UserWarning``.
    """
    try:
        presets = _audit_presets()
        preset_keys = set(presets)
        modes = _modes()

        file_dict = _read_file_layer(path)
        f_audit = _subtable(file_dict, "audit")
        f_sanitize = _subtable(file_dict, "sanitize")
        f_so = _subtable(file_dict, "structured_output")

        # --- compliance (defaults < file < env < kwarg) ---
        compliance_val, _ = _resolve(
            "compliance",
            DEFAULT_COMPLIANCE,
            [
                ("kwargs", compliance, _str_in(preset_keys)),
                ("env", _env_setting("AGENT_SHIELD_COMPLIANCE"), _str_in(preset_keys)),
                ("file", file_dict.get("compliance"), _str_in(preset_keys)),
            ],
        )
        spec = presets[compliance_val]

        # --- audit.path ---
        audit_path_val, _ = _resolve(
            "audit.path",
            _expand(DEFAULT_AUDIT_PATH),
            [
                ("kwargs", audit_path, _coerce_path),
                ("env", _env_setting("AGENT_SHIELD_AUDIT_PATH"), _coerce_path),
                ("file", f_audit.get("path"), _coerce_path),
            ],
        )

        # --- sanitize.strict (default DERIVED from compliance tier) ---
        default_strict = compliance_val in STRICT_SANITIZE_COMPLIANCE
        strict_val, strict_tier = _resolve(
            "sanitize.strict",
            default_strict,
            [
                ("kwargs", sanitize_strict, _bool_lenient),
                ("env", _env_setting("AGENT_SHIELD_SANITIZE_STRICT"), _bool_from_str),
                ("file", f_sanitize.get("strict"), _bool_from_native),
            ],
        )
        if default_strict and not strict_val and strict_tier != "default":
            _warn(
                f"agent-shield config: explicit sanitize.strict=false (from {strict_tier}) "
                f"DOWNGRADES the {compliance_val} preset, which defaults strict=true"
            )

        # --- structured_output.mode ---
        mode_val, _ = _resolve(
            "structured_output.mode",
            DEFAULT_MODE,
            [
                ("kwargs", structured_output_mode, _str_in(modes)),
                ("env", _env_setting("AGENT_SHIELD_STRUCTURED_OUTPUT_MODE"), _str_in(modes)),
                ("file", f_so.get("mode"), _str_in(modes)),
            ],
        )

        return Config(
            compliance=compliance_val,
            audit=AuditConfig(
                path=audit_path_val,
                retention_days=spec["retention_days"],
                fail_mode=spec["fail_mode"],
                content_fields_always=spec["content_fields_always"],
            ),
            sanitize=SanitizeConfig(strict=strict_val),
            structured_output=StructuredOutputConfig(mode=mode_val),
            guard=GuardConfig(),
        )
    except Exception as e:  # noqa: BLE001 — the never-crash contract (mirrors audit._append)
        _warn(f"agent-shield config: unexpected error ({e!r}); using built-in defaults")
        return _default_config()


def _default_config() -> Config:
    """Built-in defaults; import-safe even if audit cannot be imported."""
    try:
        spec = _audit_presets()[DEFAULT_COMPLIANCE]
        retention, fail_mode, content = (
            spec["retention_days"],
            spec["fail_mode"],
            spec["content_fields_always"],
        )
    except Exception:  # noqa: BLE001
        retention, fail_mode, content = 90, "open", False
    return Config(
        compliance=DEFAULT_COMPLIANCE,
        audit=AuditConfig(
            path=_expand(DEFAULT_AUDIT_PATH),
            retention_days=retention,
            fail_mode=fail_mode,
            content_fields_always=content,
        ),
        sanitize=SanitizeConfig(strict=False),
        structured_output=StructuredOutputConfig(mode=DEFAULT_MODE),
        guard=GuardConfig(),
    )
