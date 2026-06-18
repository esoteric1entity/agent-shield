# Layer 3 — Structured Output (`agent_shield.structured_output`)

> **Shape, not intent.** This layer constrains agent / tool output to a
> **declared structure** and rejects what doesn't conform. It enforces the
> *shape* of a tool call or response — it **does not validate content or intent**:
> a perfectly-shaped object whose values are malicious (`{"action": "rm -rf /"}`)
> still passes. It is one layer of defense-in-depth, **not** a prompt-injection
> blocker. It **never executes, evals, or decodes** the validated payload.

Stdlib-only (`json`, `dataclasses`, `typing`, `re`, `math`) · never-crash on any
output / malformed JSON / huge or deeply-nested input · deterministic. Apache-2.0.

```python
from agent_shield import structured_output as so

schema = so.Schema({
    "action": str,
    "target": str,
    "args": list,
    "dry_run": (bool, False),     # (type, default) -> optional
})
result = so.enforce(output, schema)     # output: a JSON string or a dict
result.ok          # bool
result.value       # the validated dict (defaults filled) when ok, else None
result.errors      # path-qualified, deterministic strings, e.g. "$.args[2].name: expected string, got integer"
```

---

## The Schema spec grammar (one spelling per concept)

A `Schema` wraps a dict of `{key: fieldspec}`. A `fieldspec` is one of:

| Form | Meaning | Example |
|---|---|---|
| a bare type | the value must be exactly that type | `str`, `int`, `float`, `bool`, `dict`, `list`, `NoneType` |
| bare `dict` / `list` (incl. the `typing.Dict` / `typing.List` aliases) | "any object" / "any array" — contents are accepted but finite-checked and owned (deep-copied) | `dict`, `list` |
| `list[T]` | an array whose elements are all `T` | `list[str]` |
| `dict[str, T]` | an object whose values are all `T` (keys are str) | `dict[str, int]` |
| `typing.Optional[T]` / `T \| None` | nullable: `T` or an explicit JSON `null` | `Optional[int]` |
| `typing.Union[...]` | any one of the members | `Union[int, str]` |
| `typing.Literal[...]` | an enum of allowed values | `Literal["r", "w"]` |
| a nested `Schema` | a nested object | `Schema({"name": str})` |
| `(spec, default)` | **optional** field; element 1 is a default **value** | `(bool, False)` |
| `Field(spec, **constraints)` | a field carrying constraints (below) | `Field(str, min_len=2)` |

> The bare 2-tuple is reserved **exclusively** for `(type, default)` optionals.
> A union is spelled with `typing` only — a tuple whose second element is a *type*
> (e.g. `(int, str)`) is a construction-time `ValueError` (the "did you mean a
> union?" footgun), not a silent mis-validation.

### Constraints — `Field(spec, ...)`

`min_len`, `max_len` (str / list / dict length); `ge`, `le` (inclusive numeric
bounds); `pattern` (a regex the string value must match — compiled at
construction from the **trusted schema**, never from the payload); `choices` (an
allowed set, type-aware so `True` never matches `1`).

A malformed `Schema` (an instance where a type was expected, an unsupported type,
a `(type, type)` tuple, a default whose type doesn't match, a constraint on the
wrong type, or nesting past `MAX_DEPTH`) raises `ValueError` **at construction** —
a programming error caught early; `enforce()` against any runtime payload never
raises.

---

## Type matching — the int / bool / float rules

Matching is by **exact type identity** (not `isinstance`), because in Python
`bool` is a subclass of `int`:

- an `int` field accepts `5` but **rejects `True`/`False`** (a bool is not an int here);
- a `bool` field accepts `True`/`False` but **rejects `0`/`1`/`1.0`**;
- a `float` field accepts `1.0` **and `1`** — int **widens** to float, because JSON
  emits `1` (not `1.0`) for whole numbers (a documented widening; the reverse,
  float→int, is **not** allowed);
- a `str` field rejects `bytes`; `null` validates only where `NoneType` is accepted;
- `Literal`/`choices` membership is type-aware (`type(v) is type(member) and v == member`),
  so `Literal[1]` rejects `True` and `1.0`.

**`NaN` / `Infinity` are rejected** — both on the JSON-string path (via
`parse_constant`) and the dict path (via `math.isfinite`) — so `result.value` is
always finite and round-trips through `json.dumps(..., allow_nan=False)` and the
audit log.

---

## strict vs lenient, defaults, and `value`

- `enforce(output, schema, mode="strict")` (default) — an **unexpected key** is an error.
- `enforce(output, schema, mode="lenient")` — unexpected keys are **omitted** from `value`.
- In **both** modes, an absent `(type, default)` optional is filled with its default in `value`.
- `value` is a **new** dict (no aliasing of the caller's nested dicts/lists; `enforce` never mutates its input) when `ok`, and **`None`** when not (so callers must gate on `ok`).
- Errors **collect ALL** failures (not fail-fast), in **schema-declared key order** (not the attacker-controlled input order), so two payloads differing only in key order produce identical error lists. Paths are JSONPath-ish: `$`, `.key`, `[index]` — e.g. `$.args[2].name`.

The validator descends at most `MAX_DEPTH` = 100 levels (and a `Schema` spec is
capped identically at construction), so adversarial nesting can never blow the
stack.

---

## JSON-discipline helpers

LLM output that is "valid JSON wrapped in prose / a fenced block / trailing
instructions" is a classic injection tell. Both helpers use `json.JSONDecoder().raw_decode`
(string-context-aware, bracket-accurate) — **no regex on the payload** (a regex
brace-matcher is a verified ReDoS), and never execute the content.

- `expect_json(text)` — accept **only** a single bare JSON object. Rejects leading
  prose, trailing content, multiple objects, NDJSON, and ` ```json ` fenced blocks
  (in v0.1 the fence is **not** stripped — documented). Whitespace padding is allowed.
- `extract_json(text)` — pull the **first** JSON object out of surrounding text and
  ignore the rest. Bounded by `MAX_EXTRACT_LEN` (1,000,000 chars) and
  `MAX_EXTRACT_ATTEMPTS` (1000 candidate positions) so a brace-heavy input can't hang.

Both return an `EnforceResult` (never raise).

---

## Deferred to v0.2 (documented, not built)

- **Canary tokens** — a secret planted in the system prompt + a leak-check on every
  response — need a runtime hook into the model's **response stream**
  (harness/version-dependent), so they are **deferred to v0.2**. The shipped Layer 3
  enforces output *shape*; the canary is not part of v0.1.
- **pydantic interop** — accepting a caller-supplied pydantic model (duck-typed) is
  a sanctioned future option; v0.1 ships the **stdlib** validator only and imports
  no third-party package.

---

## Bypasses & limitations

- **Shape is not intent.** A well-formed object with malicious values passes — this
  layer validates structure, not content safety. Pair it with the other layers.
- **It does not block prompt injection** — it reduces the blast radius of
  "make the agent emit free-form X" by rejecting non-conforming output.
- **Never decodes / executes** the payload (no `eval`/`exec`/`b64decode`); enforced
  by an AST test in the suite.
- **`Field(pattern=...)` is your regex, run against untrusted input.** The pattern is compiled once from your (trusted) schema, but it is matched against attacker-controlled payload strings — a catastrophic-backtracking pattern is a ReDoS you author. Use linear, anchored patterns (matching is whole-string `fullmatch`).
- **Duplicate JSON keys** follow stdlib `json` (last wins); not separately surfaced in v0.1.
- ` ```json ` fenced blocks are rejected (not unwrapped) by `expect_json` in v0.1.
