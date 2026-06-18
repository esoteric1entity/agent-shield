"""agent-shield Layer 3 — Structured Output.

Constrain agent / tool output to a DECLARED structure and reject what doesn't
conform. When a tool call or response is supposed to be a typed object, free-form
text (a classic injection-payload surface) is rejected, and the shape of every
field is checked. This enforces STRUCTURE (shape), NOT content or intent — a
well-formed object whose values are malicious still passes (see docs). It is one
layer of defense-in-depth, not a prompt-injection blocker.

  schema = so.Schema({"action": str, "target": str, "args": list, "dry_run": (bool, False)})
  result = so.enforce(output, schema)        # output: JSON str | dict -> EnforceResult
  result.ok, result.value, result.errors     # value is None on failure

JSON-discipline helpers reject the "valid JSON wrapped in prose" injection tell:
  so.expect_json(text)   # accept ONLY a single bare JSON object (no prose/trailing)
  so.extract_json(text)  # pull the first JSON object out of surrounding text

Stdlib-only (json, dataclasses, typing, re, math); never-crash on any output /
malformed JSON / huge or deeply-nested input; deterministic; NEVER executes,
evals, or decodes the validated payload. pydantic interop and canary tokens are
DEFERRED to v0.2 (documented, not built). License: Apache-2.0
"""

from __future__ import annotations

import copy
import json
import math
import re
import types
import typing
from dataclasses import dataclass
from typing import Any

#: Bare types accepted in a Schema spec (typing forms list[T]/dict[str,T]/
#: Union/Optional/Literal and nested Schema are also supported — see docs).
SUPPORTED_TYPES = (str, int, float, bool, dict, list, type(None))

#: Field() constraint keywords (pinned to docs).
CONSTRAINT_KINDS = ("min_len", "max_len", "ge", "le", "pattern", "choices")

#: enforce() modes.
MODES = ("strict", "lenient")

#: Max object/array nesting the validator descends (and the cap on Schema spec
#: nesting at construction). Bounds recursion so adversarial nesting can never
#: blow the stack; far beyond any legitimate tool-call schema.
MAX_DEPTH = 100

#: Caps that keep the JSON-discipline helpers bounded in TIME, not just
#: exception-free (an uncapped brace scan is O(n^2)).
MAX_EXTRACT_LEN = 1_000_000
MAX_EXTRACT_ATTEMPTS = 1000

_MISSING = object()   # sentinel: "no default supplied" / "field absent"

# Reject NaN/Infinity LITERALS (json calls parse_constant only for the bare
# NaN/Infinity/-Infinity tokens) AND numeric OVERFLOW (1e999 -> inf is syntactically
# valid JSON routed through parse_float), so a non-finite value can never enter a
# parsed result on any of the three public surfaces.
def _reject_nonfinite(token: str) -> float:
    raise ValueError(f"non-finite JSON constant not allowed: {token}")


def _finite_float(token: str) -> float:
    v = float(token)
    if not math.isfinite(v):
        raise ValueError(f"non-finite JSON number not allowed: {token}")
    return v


_DECODER = json.JSONDecoder(parse_constant=_reject_nonfinite, parse_float=_finite_float)


def _arepr(v: object, limit: int = 60) -> str:
    """ASCII-safe, bounded repr for error messages (never raises on exotic input,
    printable on a Windows cp1252 console)."""
    out = ascii(v)
    return out if len(out) <= limit else out[: limit - 3] + "..."


_TYPE_NAMES = {str: "string", int: "integer", float: "number", bool: "boolean",
               dict: "object", list: "array", type(None): "null"}


def _typename(t: object) -> str:
    if isinstance(t, Field):          # stable name; its repr leaks a sentinel object address
        return _typename(t.spec)
    if isinstance(t, Schema):
        return "object"
    try:
        if t in _TYPE_NAMES:
            return _TYPE_NAMES[t]
    except TypeError:                 # unhashable spec
        pass
    return getattr(t, "__name__", None) or str(t)


def _safekey(k: object) -> str:
    """Stringify a key for sort-ordering / error paths without ever raising — a
    hostile dict key whose ``__str__``/``__repr__`` raises must not break the
    never-raises contract."""
    try:
        return str(k)
    except Exception:  # noqa: BLE001 — a key's __str__ may raise anything
        return f"<{type(k).__name__}@{id(k):x}>"


def _fmt(path: tuple) -> str:
    out = "$"
    for p in path:
        out += f"[{p}]" if isinstance(p, int) else f".{_safekey(p)}"
    return out


def _normalize_bare(spec):
    """Bare un-parametrized ``typing.Dict`` / ``typing.List`` behave exactly like
    the builtin ``dict`` / ``list`` ('any object' / 'any array') — so both route
    through the finite/owned container path and neither is silently asymmetric."""
    origin = typing.get_origin(spec)
    if origin is dict and not typing.get_args(spec):
        return dict
    if origin is list and not typing.get_args(spec):
        return list
    return spec


# ----------------------------------------------------------------- data shapes
@dataclass(frozen=True)
class Field:
    """A field spec carrying an optional default and constraints.

    spec:    the type/typing-form/Schema for the field.
    default: a VALUE (not a type) — supplying it makes the field optional.
    min_len/max_len: length bounds for str / list / dict.
    ge/le:   inclusive numeric bounds for int / float.
    pattern: a regex the (string) value must match (compiled at construction
             from the trusted schema — NEVER from the payload).
    choices: an allowed set of values (type-aware membership).
    """

    spec: Any
    default: Any = _MISSING
    min_len: int | None = None
    max_len: int | None = None
    ge: float | None = None
    le: float | None = None
    pattern: str | None = None
    choices: tuple | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "_pattern_re",
                           re.compile(self.pattern) if self.pattern is not None else None)


@dataclass(frozen=True)
class EnforceResult:
    """Result of enforce()/expect_json()/extract_json().

    ok:     True iff the output conformed.
    value:  the validated object (a NEW dict, defaults filled, extras dropped in
            lenient mode) when ok; None otherwise.
    errors: path-qualified, deterministic error strings (e.g. "$.args[2].name:
            expected string, got integer"); empty when ok.
    """

    ok: bool
    value: dict | None
    errors: list[str]

    def to_dict(self) -> dict:
        return {"ok": self.ok, "value": self.value, "errors": list(self.errors)}


class Schema:
    """A declared object shape. Validates its own spec eagerly at construction
    (raises ValueError on a malformed spec — a programming error), so enforce()
    against any runtime payload stays total."""

    __slots__ = ("spec",)

    def __init__(self, spec: dict) -> None:
        if not isinstance(spec, dict):
            raise ValueError("Schema spec must be a dict of {key: fieldspec}")
        for key, fieldspec in spec.items():
            if not isinstance(key, str):
                raise ValueError(f"schema keys must be str, got {_arepr(key)}")
            _validate_spec(fieldspec, 1)
        self.spec = spec

    def __repr__(self) -> str:   # pragma: no cover - debug aid
        return f"Schema({list(self.spec)!r})"


# ----------------------------------------------- schema-spec validation (eager)
def _looks_like_type(x: object) -> bool:
    return (isinstance(x, (type, Schema, Field))
            or typing.get_origin(x) is not None)


def _validate_spec(spec: object, depth: int) -> None:
    """Raise ValueError if `spec` is not a supported field spec."""
    if depth > MAX_DEPTH:
        raise ValueError(f"schema nesting exceeds MAX_DEPTH ({MAX_DEPTH})")
    spec = _normalize_bare(spec)        # bare typing.Dict/List -> builtin dict/list
    if isinstance(spec, Schema):
        return
    if isinstance(spec, Field):
        _validate_spec(spec.spec, depth + 1)
        _validate_field_constraints(spec)
        if spec.default is not _MISSING:
            _check_default(spec.default, spec.spec)
        return
    if isinstance(spec, tuple):
        if len(spec) != 2:
            raise ValueError("a tuple field spec must be (type, default)")
        inner, default = spec
        if _looks_like_type(default):
            raise ValueError(
                f"(type, default) expects a default VALUE, got a type {_arepr(default)} — "
                "for a union use typing.Union / Optional, not a tuple")
        _validate_spec(inner, depth + 1)
        _check_default(default, inner)
        return
    origin = typing.get_origin(spec)
    if origin is list:
        args = typing.get_args(spec)
        if len(args) != 1:
            raise ValueError("list[...] needs exactly one element type")
        _validate_spec(args[0], depth + 1)
        return
    if origin is dict:
        args = typing.get_args(spec)
        if args:
            if args[0] is not str:
                raise ValueError("dict[...] keys must be str (JSON keys are strings)")
            _validate_spec(args[1], depth + 1)
        return
    if origin is typing.Union or origin is types.UnionType:
        for m in typing.get_args(spec):
            _validate_spec(m, depth + 1)
        return
    if origin is typing.Literal:
        if not typing.get_args(spec):
            raise ValueError("Literal[...] needs at least one member")
        return
    if isinstance(spec, type):
        if spec not in SUPPORTED_TYPES:
            raise ValueError(f"unsupported type {_typename(spec)}; supported: "
                             f"{tuple(_typename(t) for t in SUPPORTED_TYPES)}")
        return
    raise ValueError(f"invalid field spec {_arepr(spec)} (expected a type, a typing "
                     "form, a Schema, a Field, or a (type, default) tuple)")


def _validate_field_constraints(f: Field) -> None:
    for name in ("min_len", "max_len"):
        v = getattr(f, name)
        if v is not None and not (type(v) is int and v >= 0):
            raise ValueError(f"{name} must be a non-negative int, got {_arepr(v)}")
    for name in ("ge", "le"):
        v = getattr(f, name)
        if v is not None and not isinstance(v, (int, float)) or isinstance(v, bool):
            if v is not None:
                raise ValueError(f"{name} must be a number, got {_arepr(v)}")
    if f.choices is not None and not isinstance(f.choices, (tuple, list, set, frozenset)):
        raise ValueError(f"choices must be a collection, got {_arepr(f.choices)}")


def _check_default(default: object, spec: object) -> None:
    errs: list[str] = []
    _validate(default, spec, (), errs, 0, "lenient")
    if errs:
        raise ValueError(f"default {_arepr(default)} does not match its declared type")


# --------------------------------------------------------- runtime type matching
def _type_matches(value: object, declared: type) -> bool:
    """Exact, type-identity matching (NOT isinstance) so bool never satisfies int
    and 0/1 never satisfy bool. int widens to float (JSON emits 1, not 1.0, for
    whole numbers); non-finite floats are rejected."""
    if declared is bool:
        return type(value) is bool
    if declared is int:
        return type(value) is int
    if declared is float:
        return (type(value) is float and math.isfinite(value)) or type(value) is int
    if declared is str:
        return type(value) is str
    if declared is type(None):
        return value is None
    if declared is dict:
        return type(value) is dict
    if declared is list:
        return type(value) is list
    return type(value) is declared


def _copy_finite(value, path, errors, depth):
    """Deep-copy a bare dict/list leaf so result.value OWNS its contents (no
    aliasing of the caller's nested objects) and is FINITE (rejects a non-finite
    float anywhere inside — closes the overflow-to-inf gap on the dict-input path).
    Depth-bounded so an adversarially-nested bare container can't blow the stack."""
    if depth > MAX_DEPTH:
        errors.append(f"{_fmt(path)}: exceeds max nesting depth {MAX_DEPTH}")
        return _MISSING
    if type(value) is float and not math.isfinite(value):
        errors.append(f"{_fmt(path)}: non-finite number not allowed")
        return _MISSING
    if type(value) is dict:
        out, bad = {}, False
        for k in value:
            cv = _copy_finite(value[k], path + (k,), errors, depth + 1)
            if cv is _MISSING:
                bad = True
            else:
                out[k] = cv
        return _MISSING if bad else out
    if type(value) is list:
        out, bad = [], False
        for i, item in enumerate(value):
            cv = _copy_finite(item, path + (i,), errors, depth + 1)
            if cv is _MISSING:
                bad = True
            else:
                out.append(cv)
        return _MISSING if bad else out
    return value


# --------------------------------------------------------- the validating walk
def _validate(value, spec, path, errors, depth, mode):
    """Validate `value` against `spec`, appending path-qualified errors. Returns
    the (rebuilt) value, or _MISSING on error. Recursion is bounded by the
    schema's nesting (capped at construction) and by MAX_DEPTH."""
    if depth > MAX_DEPTH:
        errors.append(f"{_fmt(path)}: exceeds max nesting depth {MAX_DEPTH}")
        return _MISSING

    spec = _normalize_bare(spec)        # bare typing.Dict/List -> builtin dict/list (finite + owned)
    if isinstance(spec, Field):
        out = _validate(value, spec.spec, path, errors, depth, mode)
        if out is not _MISSING:
            _check_constraints(out, spec, path, errors)
        return out

    if isinstance(spec, Schema):
        return _validate_object(value, spec, path, errors, depth, mode)

    origin = typing.get_origin(spec)
    if origin is list:
        return _validate_list(value, typing.get_args(spec)[0], path, errors, depth, mode)
    if origin is dict:
        args = typing.get_args(spec)
        return _validate_map(value, args[1] if args else None, path, errors, depth, mode)
    if origin is typing.Union or origin is types.UnionType:
        return _validate_union(value, typing.get_args(spec), path, errors, depth, mode)
    if origin is typing.Literal:
        return _validate_literal(value, typing.get_args(spec), path, errors)

    # bare type
    if _type_matches(value, spec):
        if spec is dict or spec is list:     # own + finiteness-check the container leaf
            return _copy_finite(value, path, errors, depth)
        return value
    got = _typename(type(value))
    if isinstance(value, float) and not math.isfinite(value):
        got = "non-finite number"
    errors.append(f"{_fmt(path)}: expected {_typename(spec)}, got {got}")
    return _MISSING


def _unpack_field(fieldspec):
    """-> (spec, default, optional)."""
    if isinstance(fieldspec, Field):
        return fieldspec, fieldspec.default, fieldspec.default is not _MISSING
    if isinstance(fieldspec, tuple):
        return fieldspec[0], fieldspec[1], True
    return fieldspec, _MISSING, False


def _validate_object(value, schema, path, errors, depth, mode):
    if type(value) is not dict:
        errors.append(f"{_fmt(path)}: expected object, got {_typename(type(value))}")
        return _MISSING
    out: dict = {}
    for key, fieldspec in schema.spec.items():
        spec, default, optional = _unpack_field(fieldspec)
        if key not in value:
            if optional:
                out[key] = copy.deepcopy(default)   # fresh per call — no shared-mutable-default aliasing
            else:
                errors.append(f"{_fmt(path + (key,))}: missing required key")
            continue
        v = _validate(value[key], spec, path + (key,), errors, depth + 1, mode)
        if v is not _MISSING:
            out[key] = v
    if mode == "strict":
        for k in sorted(set(value) - set(schema.spec), key=_safekey):  # _safekey: total order, never raises even if a key's __str__ raises
            errors.append(f"{_fmt(path + (k,))}: unexpected key")
    return out


def _validate_list(value, elemspec, path, errors, depth, mode):
    if type(value) is not list:
        errors.append(f"{_fmt(path)}: expected array, got {_typename(type(value))}")
        return _MISSING
    out = []
    for i, item in enumerate(value):
        v = _validate(item, elemspec, path + (i,), errors, depth + 1, mode)
        out.append(item if v is _MISSING else v)
    return out


def _validate_map(value, valuespec, path, errors, depth, mode):
    if type(value) is not dict:
        errors.append(f"{_fmt(path)}: expected object, got {_typename(type(value))}")
        return _MISSING
    if valuespec is None:                      # defensive: bare typing.Dict is normalized to dict upstream
        return _copy_finite(value, path, errors, depth)
    out = {}
    for k in sorted(value, key=_safekey):      # _safekey: deterministic + never raises even if a key's __str__ raises
        v = _validate(value[k], valuespec, path + (k,), errors, depth + 1, mode)
        out[k] = value[k] if v is _MISSING else v
    return out


def _validate_union(value, members, path, errors, depth, mode):
    for m in members:
        sub: list[str] = []
        v = _validate(value, m, path, sub, depth, mode)
        if not sub and v is not _MISSING:
            return v
    names = " | ".join(_typename(m) for m in members)
    errors.append(f"{_fmt(path)}: expected one of ({names}), got {_typename(type(value))}")
    return _MISSING


def _validate_literal(value, members, path, errors):
    for m in members:
        if type(value) is type(m) and value == m:
            return value
    errors.append(f"{_fmt(path)}: {_arepr(value)} is not an allowed value "
                  f"(expected one of {_arepr(list(members))})")
    return _MISSING


def _check_constraints(value, f: Field, path, errors):
    if f.min_len is not None or f.max_len is not None:
        try:
            n = len(value)
        except TypeError:
            errors.append(f"{_fmt(path)}: length constraint on a non-sized value")
            return
        if f.min_len is not None and n < f.min_len:
            errors.append(f"{_fmt(path)}: length {n} below minimum {f.min_len}")
        if f.max_len is not None and n > f.max_len:
            errors.append(f"{_fmt(path)}: length {n} above maximum {f.max_len}")
    if (f.ge is not None or f.le is not None):
        if isinstance(value, bool) or not isinstance(value, (int, float)) \
                or (isinstance(value, float) and not math.isfinite(value)):
            errors.append(f"{_fmt(path)}: numeric range constraint on a non-number")
        else:
            if f.ge is not None and value < f.ge:
                errors.append(f"{_fmt(path)}: value {_arepr(value)} below minimum {f.ge}")
            if f.le is not None and value > f.le:
                errors.append(f"{_fmt(path)}: value {_arepr(value)} above maximum {f.le}")
    if f.pattern is not None and type(value) is str:
        if f._pattern_re.fullmatch(value) is None:   # whole-string match: a substring must not satisfy
            errors.append(f"{_fmt(path)}: does not match required pattern")
    elif f.pattern is not None:
        errors.append(f"{_fmt(path)}: pattern constraint on a non-string")
    if f.choices is not None:
        if not any(type(value) is type(c) and value == c for c in f.choices):
            errors.append(f"{_fmt(path)}: {_arepr(value)} is not an allowed value")


# --------------------------------------------------------------- public API
def enforce(output: object, schema: Schema, *, mode: str = "strict") -> EnforceResult:
    """Validate `output` (a JSON string, bytes, or a dict) against `schema`.
    Returns an EnforceResult; never raises on any runtime payload."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    if isinstance(output, (str, bytes, bytearray)):
        text = (output if isinstance(output, str)
                else bytes(output).decode("utf-8", errors="replace"))
        try:
            data = json.loads(text, parse_constant=_reject_nonfinite, parse_float=_finite_float)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return EnforceResult(False, None, ["$: invalid JSON"])
    elif isinstance(output, dict):
        data = output
    else:
        return EnforceResult(False, None,
                             [f"$: expected a JSON object, got {_typename(type(output))}"])
    if type(data) is not dict:
        return EnforceResult(False, None,
                             [f"$: expected a JSON object, got {_typename(type(data))}"])
    errors: list[str] = []
    try:
        value = _validate_object(data, schema, (), errors, 0, mode)
    except RecursionError:   # defensive backstop; depth is schema-bounded so this should not fire
        return EnforceResult(False, None, ["$: input too deeply nested"])
    if errors:
        return EnforceResult(False, None, errors)
    return EnforceResult(True, value, [])


def expect_json(text: object) -> EnforceResult:
    """Accept ONLY a single bare JSON object: no leading/trailing prose, no
    multiple objects, no fenced code block (rejected in v0.1). Whitespace padding
    is allowed. Bracket-accurate via raw_decode — no regex on the payload."""
    s = _as_text(text)
    if s is None:
        return EnforceResult(False, None, ["$: expected text"])
    if len(s) > MAX_EXTRACT_LEN:
        return EnforceResult(False, None, ["$: input too large"])
    t = s.strip()
    try:
        obj, end = _DECODER.raw_decode(t)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return EnforceResult(False, None, ["$: not a single JSON object"])
    if type(obj) is not dict:
        return EnforceResult(False, None,
                             [f"$: expected a JSON object, got {_typename(type(obj))}"])
    if t[end:].strip() != "":
        return EnforceResult(False, None, ["$: trailing content after the JSON object"])
    return EnforceResult(True, obj, [])


def extract_json(text: object) -> EnforceResult:
    """Pull the FIRST JSON object out of surrounding text (prose, logs). Bounded
    by MAX_EXTRACT_LEN and MAX_EXTRACT_ATTEMPTS so a brace-heavy input can't hang.
    Returns the first '{' that decodes to an object; never executes the payload."""
    s = _as_text(text)
    if s is None or len(s) > MAX_EXTRACT_LEN:
        return EnforceResult(False, None, ["$: no JSON object found"])
    i = s.find("{")
    attempts = 0
    while i != -1 and attempts < MAX_EXTRACT_ATTEMPTS:
        attempts += 1
        try:
            obj, _end = _DECODER.raw_decode(s, i)
            if type(obj) is dict:
                return EnforceResult(True, obj, [])
        except (json.JSONDecodeError, ValueError, RecursionError):
            pass
        i = s.find("{", i + 1)
    return EnforceResult(False, None, ["$: no JSON object found"])


def _as_text(text: object) -> str | None:
    if isinstance(text, str):
        return text
    if isinstance(text, (bytes, bytearray)):
        return bytes(text).decode("utf-8", errors="replace")
    return None
