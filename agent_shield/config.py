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
import sys
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

#: Error-path POSTURE defaults (guard slice). These govern behavior when an
#: evaluation cannot complete; they NEVER relax a built-in detection pattern.
#: ``error_policy`` here is the NEUTRAL default — harness-specific defaults
#: (e.g. CC=observe) are layered in a later task, not here.
ERROR_POLICIES = ("open", "closed", "ask", "observe")
DEFAULT_ERROR_POLICY = "closed"
DEFAULT_UNATTENDED = False
DEFAULT_ASK_TIMEOUT_MS = 60000
DEFAULT_SPAWN_TIMEOUT_MS = 5000
DEFAULT_HEALTH_PROBE = True

#: Semantics of ``GuardConfig.health_probe`` (E4 LOCKED). When ``True``, a tripped
#: circuit-breaker MAY perform periodic re-probes to detect guard recovery; when
#: ``False``, re-probing is disabled. There is **NO bootstrap grace** — the breaker
#: denies from call 1 regardless of this value. The actual re-probe cadence, TTL,
#: and breaker implementation live in the harness adapters (Phases C2/D2).
HEALTH_PROBE_ENABLES_REPROBE = True
HEALTH_PROBE_NO_BOOTSTRAP_GRACE = True

#: Inclusive [min, max] millisecond ranges for the posture timeouts. An int that
#: parses but falls OUTSIDE its range is rejected (default kept + a surfaced
#: UserWarning) — NOT silently clamped — matching the rest of config's
#: invalid-value handling (a value is either accepted as-given or ignored).
ASK_TIMEOUT_MS_RANGE = (1000, 600000)
SPAWN_TIMEOUT_MS_RANGE = (1000, 60000)

#: Recognized harness identifiers (for ``detect_harness`` / the ``harness=`` hint).
HARNESSES = ("openclaw", "claude_code")

#: Per-harness DEFAULT ``error_policy`` — the harness-default tier (Contract #4)
#: sits just above built-in defaults and below file/env/kwarg, so it can be
#: overridden. A harness not listed here (incl. ``None`` / unrecognized) uses the
#: NEUTRAL :data:`DEFAULT_ERROR_POLICY`.
HARNESS_ERROR_POLICY_DEFAULT = {
    "openclaw": "closed",
    "claude_code": "observe",
}

#: Env var naming the running HARNESS (highest-priority signal for
#: ``detect_harness``). Empty / whitespace-only is treated as unset.
HARNESS_ENV = "AGENT_SHIELD_HARNESS"

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
    "AGENT_SHIELD_ERROR_POLICY": "guard.error_policy",
    "AGENT_SHIELD_UNATTENDED": "guard.unattended",
    "AGENT_SHIELD_ASK_TIMEOUT_MS": "guard.ask_timeout_ms",
    "AGENT_SHIELD_SPAWN_TIMEOUT_MS": "guard.spawn_timeout_ms",
    "AGENT_SHIELD_HEALTH_PROBE": "guard.health_probe",
}

def _strict_sanitize_presets() -> frozenset[str]:
    """Derive the strict-sanitize preset set from the single-source audit table.

    This closes a forward-compat gap: a future high-posture preset only needs to
    set ``sanitize_strict = True`` in ``audit.PRESETS``; config automatically
    honors it without a second hard-coded list.
    """
    from agent_shield import audit  # single-sourced from the audit table

    return frozenset({name for name, spec in audit.PRESETS.items() if spec.get("sanitize_strict")})


#: Compliance tiers that tighten input sanitization by default. A subset of the
#: audit preset names (pinned by test); an unlisted preset defaults to non-strict.
STRICT_SANITIZE_COMPLIANCE = _strict_sanitize_presets()

#: Compliance tiers that FORCE ``guard.error_policy = "closed"`` at the TOP of
#: precedence — above the harness-default, the config file, the env var, and any
#: explicit input (Contract #4). These are the "tightening" presets: the ones
#: that already tighten posture elsewhere (strict sanitization + audit fail-closed),
#: so a fail-OPEN error posture would contradict the preset's own promise. If the
#: normal precedence ladder resolved anything other than ``"closed"`` for such a
#: preset, that override is IGNORED and a UserWarning is surfaced. A NON-tightening
#: preset (or no preset) forces nothing — the ladder result stands. This governs
#: ``error_policy`` ONLY; it is DECOUPLED from the preset-derived ``audit.fail_mode``.
FORCE_CLOSED_COMPLIANCE = frozenset({"healthcare", "biotech"})

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
    """Runtime-guard slice. Carries ERROR-PATH POSTURE only — how the guard
    behaves when an evaluation cannot complete. By design these can NEVER relax
    a built-in detection pattern (pattern add-ons like ``extra_red`` /
    ``extra_yellow`` remain deferred with their own pre-mortem, because a config
    that could remove/relax a built-in pattern would be a policy-weakening
    downgrade in a security tool).

    Fields:
      - ``error_policy``: posture when evaluation fails — one of
        :data:`ERROR_POLICIES` (``open`` | ``closed`` | ``ask`` | ``observe``).
        The NEUTRAL default is ``closed``; harness-specific defaults are layered
        in a later task, not here.
      - ``unattended``: whether the guard runs without an interactive operator.
      - ``ask_timeout_ms`` / ``spawn_timeout_ms``: posture timeouts (raw int at
        this layer; range validation is layered later).
      - ``health_probe``: whether a tripped circuit-breaker performs periodic
        re-probes to detect guard recovery (``True``) or stays tripped without
        re-probing (``False``). **No bootstrap grace** — the breaker denies from
        call 1; this field only controls recovery re-probing after the initial trip.
    """

    error_policy: str = DEFAULT_ERROR_POLICY
    unattended: bool = DEFAULT_UNATTENDED
    ask_timeout_ms: int = DEFAULT_ASK_TIMEOUT_MS
    spawn_timeout_ms: int = DEFAULT_SPAWN_TIMEOUT_MS
    health_probe: bool = DEFAULT_HEALTH_PROBE

    def to_dict(self) -> dict:
        return {
            "error_policy": self.error_policy,
            "unattended": self.unattended,
            "ask_timeout_ms": self.ask_timeout_ms,
            "spawn_timeout_ms": self.spawn_timeout_ms,
            "health_probe": self.health_probe,
        }


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


def _int_from_str(raw):
    """Env tier: values are always strings — parse a base-10 integer. A non-int
    (e.g. ``"soon"``, a float string like ``"12.5"``) is rejected so the resolver
    warns and keeps the default. NOTE: this is the bare parser; range validation
    is layered on top via :func:`_int_in_range` (a value that parses as an int is
    accepted by this parser regardless of magnitude)."""
    if isinstance(raw, str):
        try:
            return True, int(raw.strip())
        except (TypeError, ValueError):
            return False, None
    return False, None


def _int_in_range(lo, hi):
    """Factory: parse a base-10 int (via :func:`_int_from_str`) and require it to
    fall in the INCLUSIVE ``[lo, hi]`` range. A non-int OR an out-of-range int is
    rejected (ok=False) so the resolver warns and keeps the field default — the
    value is NOT clamped (config either accepts a value as-given or ignores it,
    consistent with every other tier/coercer in this module)."""

    def coerce(raw):
        ok, val = _int_from_str(raw)
        if ok and lo <= val <= hi:
            return True, val
        return False, None

    return coerce


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
# Harness detection (Contract #4) — total: returns "openclaw" | "claude_code" | None
# =============================================================================
def detect_harness() -> str | None:
    """Best-effort detection of the running harness. **Never raises.**

    Branch order (LOCKED):
      (a) ``$AGENT_SHIELD_HARNESS`` if set to a recognized value (``openclaw`` /
          ``claude_code``). An empty/whitespace value is treated as unset; an
          *unrecognized* value warns and is treated as unset (so detection falls
          through to the heuristic), mirroring config's invalid-value handling.
      (b) a conservative ``sys.argv[0]`` basename heuristic — the installed
          console-script names: ``agent-shield-openclaw-guard`` -> ``openclaw``;
          the Claude Code PreToolUse hook entries ``agent-shield-bash-guard`` /
          ``agent-shield-write-guard`` -> ``claude_code``. Only CLEAR signals
          match; anything else is ignored.
      (c) ``None`` — unknown harness; the caller uses the neutral default.

    The adapters call this and pass the result as ``config.load(harness=...)``.
    """
    try:
        env = _env_setting(HARNESS_ENV)
        if env is not None:
            if env in HARNESSES:
                return env
            _warn(
                f"agent-shield config: ignoring unrecognized {HARNESS_ENV}={env!r} "
                f"(expected one of {HARNESSES}); detecting from argv instead"
            )

        argv = getattr(sys, "argv", None) or []
        argv0 = argv[0] if argv else ""
        if not isinstance(argv0, str):
            return None
        # EXACT basename match (conservative): a substring test would
        # false-positive on a wrapper like ``my-agent-shield-openclaw-guard-x``.
        # Only the literal installed console-script names (optionally ``.exe``)
        # count as a clear signal.
        base = os.path.basename(argv0).lower()
        if base.endswith(".exe"):
            base = base[:-4]
        if base == "agent-shield-openclaw-guard":
            return "openclaw"
        if base in ("agent-shield-bash-guard", "agent-shield-write-guard"):
            return "claude_code"
        return None
    except Exception:  # noqa: BLE001 — detection is best-effort; never crash a caller
        return None


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
    harness=None,
):
    """Load configuration. **Total — never raises into a caller** for any input.

    Args:
        path: explicit config-file path (highest-priority search leg).
        compliance / audit_path / sanitize_strict / structured_output_mode:
            explicit per-field overrides (highest precedence of all tiers).
        harness: optional harness hint (``"openclaw"`` / ``"claude_code"``;
            ``None`` / unrecognized -> neutral). The adapters detect this via
            :func:`detect_harness` and pass it. It seeds the HARNESS-DEFAULT tier
            (Contract #4): built-in defaults < harness-default < file < env <
            kwargs — so it sets the DEFAULT ``error_policy`` for the harness, which
            the config file and ``AGENT_SHIELD_ERROR_POLICY`` still override
            (``error_policy`` has no explicit ``load()`` kwarg).

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
        f_guard = _subtable(file_dict, "guard")

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

        # --- guard slice (error-path POSTURE) ---
        # These never relax a built-in pattern; an invalid value falls back to
        # the next-lower tier + a surfaced UserWarning (via _resolve).
        #
        # error_policy precedence (Contract #4): built-in < HARNESS-DEFAULT <
        # file < env < kwarg. The harness-default tier is seeded as _resolve's
        # `default` arg (the lowest fallback) — so it sets the per-harness
        # DEFAULT but any file/env value above it still wins. A None/unrecognized
        # harness hint -> the NEUTRAL DEFAULT_ERROR_POLICY ("closed").
        harness_default_policy = HARNESS_ERROR_POLICY_DEFAULT.get(harness, DEFAULT_ERROR_POLICY)
        error_policy_val, _ = _resolve(
            "guard.error_policy",
            harness_default_policy,
            [
                ("env", _env_setting("AGENT_SHIELD_ERROR_POLICY"), _str_in(ERROR_POLICIES)),
                ("file", f_guard.get("error_policy"), _str_in(ERROR_POLICIES)),
            ],
        )
        # A tightening compliance preset (healthcare / biotech) FORCES error_policy
        # to "closed" ABOVE every tier (Contract #4): the preset already promises a
        # fail-closed posture (strict sanitize + audit fail-closed), so a fail-OPEN
        # error posture would contradict it. This sits on TOP of the resolved ladder
        # value — if that value was anything OTHER than "closed" (an open/observe/ask
        # override arrived via harness-default/file/env), the override is IGNORED and
        # a UserWarning is surfaced; if it was already "closed" (no override attempt)
        # we force the same value silently. DECOUPLED from audit.fail_mode (that is
        # preset-derived via audit.PRESETS on a separate path; not touched here).
        if compliance_val in FORCE_CLOSED_COMPLIANCE and error_policy_val != "closed":
            _warn(
                f"agent-shield config: the {compliance_val} compliance preset forces "
                f"guard.error_policy='closed'; ignoring the resolved {error_policy_val!r}"
            )
            error_policy_val = "closed"
        unattended_val, _ = _resolve(
            "guard.unattended",
            DEFAULT_UNATTENDED,
            [("env", _env_setting("AGENT_SHIELD_UNATTENDED"), _bool_from_str)],
        )
        # Timeouts: an int OUTSIDE its inclusive range is rejected (default kept +
        # warning), NOT clamped — consistent with every other coercer here.
        ask_timeout_val, _ = _resolve(
            "guard.ask_timeout_ms",
            DEFAULT_ASK_TIMEOUT_MS,
            [("env", _env_setting("AGENT_SHIELD_ASK_TIMEOUT_MS"), _int_in_range(*ASK_TIMEOUT_MS_RANGE))],
        )
        spawn_timeout_val, _ = _resolve(
            "guard.spawn_timeout_ms",
            DEFAULT_SPAWN_TIMEOUT_MS,
            [("env", _env_setting("AGENT_SHIELD_SPAWN_TIMEOUT_MS"), _int_in_range(*SPAWN_TIMEOUT_MS_RANGE))],
        )
        health_probe_val, _ = _resolve(
            "guard.health_probe",
            DEFAULT_HEALTH_PROBE,
            [("env", _env_setting("AGENT_SHIELD_HEALTH_PROBE"), _bool_from_str)],
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
            guard=GuardConfig(
                error_policy=error_policy_val,
                unattended=unattended_val,
                ask_timeout_ms=ask_timeout_val,
                spawn_timeout_ms=spawn_timeout_val,
                health_probe=health_probe_val,
            ),
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
