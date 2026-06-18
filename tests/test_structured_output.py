"""
test_structured_output.py — Layer 3 (Structured Output) behavioral suite
========================================================================

TDD spec for agent_shield/structured_output.py: a stdlib schema validator +
JSON-discipline helpers. Covers the Schema DSL, the int/bool/float type traps,
constraints, strict/lenient, collect-all path-qualified errors, the
expect_json/extract_json helpers, never-crash/recursion/DoS bounds, the
no-execution guarantee, and API/audit-handoff consistency.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import ast
import json
import math
import time
import typing
from pathlib import Path

import pytest

from agent_shield import audit, structured_output as so

_SRC = Path(so.__file__).read_text(encoding="utf-8")


def _errtext(r):
    return " || ".join(r.errors)


# -------------------------------------------------- schema-validation (happy + structural)
def test_required_present_and_types_match_ok():
    s = so.Schema({"action": str, "target": str, "args": list, "dry_run": (bool, False)})
    r = so.enforce({"action": "run", "target": "/x", "args": []}, s)
    assert r.ok and r.errors == []
    assert r.value == {"action": "run", "target": "/x", "args": [], "dry_run": False}


def test_missing_required_key_errors():
    r = so.enforce({"action": "run"}, so.Schema({"action": str, "target": str}))
    assert not r.ok and r.value is None
    assert any("$.target" in e and "missing" in e for e in r.errors)


def test_nested_object_via_subschema_validates():
    s = so.Schema({"user": so.Schema({"name": str, "zip": str})})
    r = so.enforce({"user": {"name": "a", "zip": 90210}}, s)
    assert not r.ok
    assert any("$.user.zip" in e for e in r.errors)


def test_typed_list_element_type_enforced():
    s = so.Schema({"tags": typing.List[str]})
    assert not so.enforce({"tags": ["a", 5, "c"]}, s).ok
    assert any("$.tags[1]" in e for e in so.enforce({"tags": ["a", 5, "c"]}, s).errors)
    assert so.enforce({"tags": ["a", "b"]}, s).ok


def test_typed_dict_map_value_type_enforced():
    s = so.Schema({"scores": typing.Dict[str, int]})
    r = so.enforce({"scores": {"x": 1, "y": "no"}}, s)
    assert not r.ok and any("$.scores.y" in e for e in r.errors)


def test_union_accepts_members_rejects_others():
    s = so.Schema({"v": typing.Union[int, str]})
    assert so.enforce({"v": 1}, s).ok
    assert so.enforce({"v": "x"}, s).ok
    assert not so.enforce({"v": 1.5}, s).ok
    # Optional[int] and int|None behave identically; null validates a nullable
    for spec in (typing.Optional[int], int | None):
        s2 = so.Schema({"v": spec})
        assert so.enforce({"v": None}, s2).ok
        assert so.enforce({"v": 3}, s2).ok
        assert not so.enforce({"v": "x"}, s2).ok


def test_literal_enum_membership():
    s = so.Schema({"mode": typing.Literal["a", "b"]})
    assert so.enforce({"mode": "a"}, s).ok
    r = so.enforce({"mode": "c"}, s)
    assert not r.ok and any("$.mode" in e for e in r.errors)


# -------------------------------------------------- type-traps
def test_bool_not_accepted_as_int():
    s = so.Schema({"x": int})
    assert not so.enforce({"x": True}, s).ok
    assert not so.enforce({"x": False}, s).ok
    assert so.enforce({"x": 5}, s).ok


def test_int_and_float_not_accepted_as_bool():
    s = so.Schema({"x": bool})
    for bad in (1, 0, 1.0):
        assert not so.enforce({"x": bad}, s).ok
    assert so.enforce({"x": True}, s).ok


def test_int_widens_to_float_but_float_not_to_int():
    assert so.enforce({"x": 3}, so.Schema({"x": float})).ok        # documented widening
    assert not so.enforce({"x": 3.0}, so.Schema({"x": int})).ok    # no narrowing


def test_literal_type_aware_equality():
    assert not so.enforce({"x": True}, so.Schema({"x": typing.Literal[1, 2]})).ok
    assert not so.enforce({"x": 1.0}, so.Schema({"x": typing.Literal[1, 2]})).ok
    assert not so.enforce({"x": 1}, so.Schema({"x": typing.Literal[True]})).ok
    assert so.enforce({"x": 1}, so.Schema({"x": typing.Literal[1, 2]})).ok


def test_nan_infinity_rejected_string_and_dict():
    s = so.Schema({"x": float})
    for bad in ('{"x": NaN}', '{"x": Infinity}', '{"x": -Infinity}'):
        assert not so.enforce(bad, s).ok
    assert not so.enforce({"x": float("nan")}, s).ok
    assert not so.enforce({"x": float("inf")}, s).ok


def test_str_field_rejects_bytes_and_none_distinct():
    assert not so.enforce({"x": b"hi"}, so.Schema({"x": str})).ok
    assert so.enforce({"x": None}, so.Schema({"x": type(None)})).ok
    assert not so.enforce({"x": None}, so.Schema({"x": str})).ok


# -------------------------------------------------- constraints
def test_length_constraints():
    s = so.Schema({"x": so.Field(str, min_len=2, max_len=4)})
    assert not so.enforce({"x": "a"}, s).ok
    assert not so.enforce({"x": "abcde"}, s).ok
    assert so.enforce({"x": "abc"}, s).ok


def test_numeric_range_constraints():
    s = so.Schema({"x": so.Field(int, ge=0, le=10)})
    assert not so.enforce({"x": -1}, s).ok
    assert not so.enforce({"x": 11}, s).ok
    assert so.enforce({"x": 5}, s).ok


def test_regex_pattern_constraint_is_data_only():
    s = so.Schema({"x": so.Field(str, pattern=r"^\d{3}$")})
    assert so.enforce({"x": "123"}, s).ok
    assert not so.enforce({"x": "abc"}, s).ok


def test_choices_allowed_values():
    s = so.Schema({"x": so.Field(str, choices=("r", "w"))})
    assert so.enforce({"x": "r"}, s).ok
    r = so.enforce({"x": "z"}, s)
    assert not r.ok and any("$.x" in e for e in r.errors)


# -------------------------------------------------- strict / lenient
def test_strict_rejects_unexpected_keys():
    s = so.Schema({"a": int})
    r = so.enforce({"a": 1, "b": 2}, s, mode="strict")
    assert not r.ok and any("$.b" in e and "unexpected" in e for e in r.errors)


def test_lenient_ignores_and_omits_extras():
    s = so.Schema({"a": int})
    r = so.enforce({"a": 1, "b": 2}, s, mode="lenient")
    assert r.ok and r.value == {"a": 1}     # extra omitted


def test_defaults_filled_identically_both_modes():
    s = so.Schema({"a": int, "b": (str, "def")})
    for mode in ("strict", "lenient"):
        r = so.enforce({"a": 1}, s, mode=mode)
        assert r.ok and r.value == {"a": 1, "b": "def"}
    r2 = so.enforce({"a": 1, "b": "x"}, s)
    assert r2.value["b"] == "x"             # present overrides default


def test_explicit_null_vs_absent_optional():
    s = so.Schema({"a": (typing.Optional[str], None)})
    assert so.enforce({}, s).value == {"a": None}            # absent -> default
    assert so.enforce({"a": None}, s).ok                     # explicit null ok (nullable)
    assert not so.enforce({"a": None}, so.Schema({"a": (str, "d")})).ok  # null not 'absent'


# -------------------------------------------------- error collection
def test_collects_all_errors_not_fail_fast():
    s = so.Schema({"a": int, "args": typing.List[int]})
    r = so.enforce({"args": ["x", 2], "z": 9}, s, mode="strict")
    assert not r.ok
    joined = _errtext(r)
    assert "$.a" in joined and "missing" in joined    # missing required
    assert "$.args[0]" in joined                       # wrong element type
    assert "$.z" in joined and "unexpected" in joined  # strict extra
    assert len(r.errors) >= 3


def test_error_order_deterministic_across_key_order():
    s = so.Schema({"a": int, "b": int, "c": int})
    r1 = so.enforce({"a": "x", "b": "y", "c": "z"}, s)
    r2 = so.enforce({"c": "z", "b": "y", "a": "x"}, s)
    assert r1.errors == r2.errors           # schema-order traversal, not input order


def test_path_format_dollar_bracket_dot():
    s = so.Schema({"args": typing.List[so.Schema({"name": str})]})
    r = so.enforce({"args": [{"name": "ok"}, {"name": "ok"}, {"name": 5}]}, s)
    assert any("$.args[2].name" in e for e in r.errors)


# -------------------------------------------------- JSON-discipline helpers
def test_expect_json_accepts_clean_object_only():
    assert so.expect_json('  {"a":1}  ').ok
    for bad in ("5", '"hi"', "[1,2]", "true", "null"):
        assert not so.expect_json(bad).ok


def test_expect_json_rejects_prose_trailing_multiple_fenced():
    for bad in ('prefix {"a":1}', '{"a":1} trailing', '{"a":1}{"b":2}',
                '{"a":1}\n{"b":2}', '```json\n{"a":1}\n```'):
        assert not so.expect_json(bad).ok, bad


def test_extract_json_pulls_first_object_from_prose():
    r = so.extract_json('here is the result: {"a": 1, "b": "}"} done')
    assert r.ok and r.value == {"a": 1, "b": "}"}    # raw_decode is string-aware


def test_extract_json_multiple_objects_takes_first():
    r = so.extract_json('{"a":1}{"b":2}')
    assert r.ok and r.value == {"a": 1}


def test_json_helpers_no_redos_no_regex_on_payload():
    adversarial = "{" * 50_000 + "x" + "}" * 50_000
    t0 = time.perf_counter()
    so.extract_json(adversarial)
    so.expect_json(adversarial)
    assert time.perf_counter() - t0 < 2.0


# -------------------------------------------------- never-crash / recursion / DoS
def test_enforce_deeply_nested_string_never_crashes():
    s = so.Schema({"a": int})
    deep = '{"a":' * 3000 + "1" + "}" * 3000
    r = so.enforce(deep, s)
    assert not r.ok and r.value is None     # parse RecursionError/JSONDecodeError caught


def test_enforce_huge_int_string_never_crashes():
    r = so.enforce("1" + "0" * 1_000_000, so.Schema({"a": int}))
    assert not r.ok


def test_extract_json_bounded_cost_and_oversize():
    t0 = time.perf_counter()
    assert not so.extract_json("{x" * 100_000).ok
    assert time.perf_counter() - t0 < 2.0
    big = "{" + "a" * (so.MAX_EXTRACT_LEN + 10)
    assert not so.extract_json(big).ok      # over cap, returns without scanning


@pytest.mark.parametrize("bad", [
    None, b'{"a":1}', "5", "[]", '"hi"', "", "not json", '{"a":',
    "{" * 200, '{"a": 1e999}',
])
def test_enforce_never_crash_parametrized(bad):
    r = so.enforce(bad, so.Schema({"a": int}))
    assert isinstance(r, so.EnforceResult)
    assert r.ok in (True, False)


def test_malformed_schema_raises_valueerror_at_construction():
    with pytest.raises(ValueError):
        so.Schema({"x": 5})                       # instance, not a type
    with pytest.raises(ValueError):
        so.Schema({"x": (int, str)})              # (type, type) — union footgun
    with pytest.raises(ValueError):
        so.Schema({"x": (int, "notint")})         # default type-mismatch
    with pytest.raises(ValueError):
        so.Schema({"x": so.Field(int, ge="bad")}) # constraint on wrong type / bad value
    # ...but a valid schema never raises on a hostile payload:
    assert not so.enforce("garbage", so.Schema({"x": int})).ok


# -------------------------------------------------- no-execution
def test_structured_output_never_executes():
    """No code-execution or decode primitive is reachable. `re.compile` (a module
    method, used only on trusted schema-author patterns) is allowed; the builtin
    `compile`/`eval`/`exec`/`__import__` are not."""
    tree = ast.parse(_SRC)
    banned_builtins = {"eval", "exec", "compile", "__import__"}
    banned_attrs = {"literal_eval", "b64decode", "urlsafe_b64decode", "unhexlify",
                    "system", "popen"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                assert fn.id not in banned_builtins, f"forbidden builtin call: {fn.id}"
            elif isinstance(fn, ast.Attribute):
                assert fn.attr not in banned_attrs, f"forbidden call: {fn.attr}"


def test_no_pydantic_in_v01():
    assert "import pydantic" not in _SRC and "from pydantic" not in _SRC
    assert "model_validate" not in _SRC


# -------------------------------------------------- API shape
def test_enforce_result_is_frozen_dataclass_with_to_dict():
    import dataclasses
    r = so.enforce({"a": 1}, so.Schema({"a": int}))
    assert dataclasses.is_dataclass(r) and r.__dataclass_params__.frozen
    d = r.to_dict()
    assert set(d) == {"ok", "value", "errors"}
    json.dumps(d)


def test_to_dict_round_trips_through_audit(tmp_path):
    r = so.enforce({"a": "x"}, so.Schema({"a": int}))   # has errors
    log = audit.AuditLog(tmp_path / "a.jsonl")
    e = log.record(action="structured_output", target="tool", outcome="reject",
                   details=r.to_dict())
    assert e is not None and log.verify().ok


def test_value_none_on_failure():
    r = so.enforce({"a": "x"}, so.Schema({"a": int}))
    assert not r.ok and r.value is None


def test_enforce_does_not_mutate_caller_dict_incl_nested():
    import copy
    s = so.Schema({"user": so.Schema({"name": str}), "tag": (str, "def")})
    inp = {"user": {"name": "a"}}
    snapshot = copy.deepcopy(inp)
    r = so.enforce(inp, s)
    assert inp == snapshot                        # caller dict untouched
    assert r.value is not inp
    assert r.value["user"] is not inp["user"]     # no nested aliasing


def test_valid_shape_malicious_payload_passes():
    s = so.Schema({"action": str, "target": str})
    assert so.enforce({"action": "rm -rf /", "target": "/"}, s).ok   # shape != intent


def test_no_top_level_clash_and_lazy_import():
    import agent_shield
    assert "structured_output" in agent_shield.__all__
    assert not hasattr(so, "Result")
    assert not hasattr(so, "Finding")


# =========================================================================
# Adversarial-review fixes.
# CODE-CHANGE: mutable-default aliasing, non-finite overflow, container aliasing,
# dict-map error order, pattern fullmatch, Field typename. Plus regression pins.
# =========================================================================
import copy as _copy


def test_mutable_default_not_shared_across_calls():
    s = so.Schema({"a": int, "items": (list, [])})
    r1 = so.enforce({"a": 1}, s)
    r1.value["items"].append("x")
    r2 = so.enforce({"a": 2}, s)
    assert r2.value["items"] == []          # fresh default each call, not a shared list


def test_overflow_to_inf_rejected_all_surfaces():
    s = so.Schema({"args": list})
    assert not so.enforce('{"args":[1e999]}', s).ok          # string path, bare list
    assert not so.enforce('{"meta":{"x":1e999}}', so.Schema({"meta": dict})).ok  # bare dict, nested
    assert not so.enforce('{"x":1e999}', so.Schema({"x": float})).ok            # float leaf
    assert not so.enforce({"args": [float("inf")]}, s).ok    # dict-input path, bare container
    assert not so.expect_json('{"x":1e999}').ok
    assert not so.extract_json('prose {"x":1e999} more').ok


def test_success_value_finite_round_trips_allow_nan_false():
    r = so.enforce('{"x": 1.5, "args":[1,2,3]}', so.Schema({"x": float, "args": list}))
    assert r.ok
    json.dumps(r.to_dict(), allow_nan=False)        # must not raise (value is finite)


def test_value_does_not_alias_caller_nested_containers():
    s = so.Schema({"meta": dict, "tags": list})
    inp = {"meta": {"k": [1, 2]}, "tags": [{"n": 1}]}
    snap = _copy.deepcopy(inp)
    r = so.enforce(inp, s)
    assert r.ok
    r.value["meta"]["k"].append(99)
    r.value["tags"][0]["n"] = 999
    assert inp == snap                              # caller untouched
    assert r.value["meta"] is not inp["meta"]
    assert r.value["tags"][0] is not inp["tags"][0]


def test_dict_map_error_order_deterministic():
    s = so.Schema({"scores": typing.Dict[str, int]})
    r1 = so.enforce({"scores": {"a": "x", "b": "y"}}, s)
    r2 = so.enforce({"scores": {"b": "y", "a": "x"}}, s)
    assert r1.errors == r2.errors


def test_pattern_is_fullmatch_not_substring():
    s = so.Schema({"x": so.Field(str, pattern=r"\d{3}")})   # unanchored
    assert so.enforce({"x": "123"}, s).ok
    assert not so.enforce({"x": "a123b"}, s).ok             # a substring must NOT pass


def test_typename_field_and_schema_are_stable_no_address():
    a = so._typename(so.Field(int, ge=0))
    b = so._typename(so.Field(int, ge=0))
    assert a == b and "0x" not in a
    assert "0x" not in so._typename(so.Schema({"x": int}))


def test_extract_json_scans_past_decoy_braces():
    assert so.extract_json('{ {x {bad {nope {"a": 1}').value == {"a": 1}


def test_strict_multi_extra_keys_sorted():
    s = so.Schema({"a": int})
    r = so.enforce({"a": 1, "zzz": 1, "mmm": 1, "aaa": 1}, s, mode="strict")
    extra = [e for e in r.errors if "unexpected" in e]
    assert extra == sorted(extra) and len(extra) == 3


def test_to_dict_errors_is_defensive_copy():
    r = so.enforce({"a": "x"}, so.Schema({"a": int}))
    d = r.to_dict()
    assert d["errors"] == r.errors and d["errors"] is not r.errors


def test_list_pep585_two_args_raises_valueerror():
    with pytest.raises(ValueError):
        so.Schema({"x": list[int, str]})            # 2-arg list[...] -> our ValueError


def test_non_str_keys_dict_path_never_crash():
    """A caller dict with non-str keys (only possible on the dict-input path —
    JSON keys are always str) must not crash sorted() in map/strict-extra paths."""
    r = so.enforce({"scores": {1: "x", "a": "y"}}, so.Schema({"scores": typing.Dict[str, int]}))
    assert isinstance(r, so.EnforceResult)
    r2 = so.enforce({"a": 1, 2: "x", "zzz": 3}, so.Schema({"a": int}), mode="strict")
    assert isinstance(r2, so.EnforceResult) and not r2.ok


def test_bare_typing_dict_and_list_behave_like_builtins():
    """Bare un-parametrized typing.Dict / typing.List == builtin dict / list:
    accepted, finite-checked, and owned (no caller aliasing) — review found the
    typing.Dict shallow-copy path leaked inf and aliased."""
    for spec in (typing.Dict, dict):
        s = so.Schema({"m": spec})
        assert not so.enforce({"m": {"x": float("inf")}}, s).ok       # finiteness (dict path)
        assert not so.enforce('{"m":{"x":1e999}}', s).ok              # finiteness (string path)
        inp = {"m": {"k": [1]}}
        r = so.enforce(inp, s)
        assert r.ok
        r.value["m"]["k"].append(9)
        assert inp == {"m": {"k": [1]}}                               # no aliasing
    for spec in (typing.List, list):
        s = so.Schema({"a": spec})
        assert so.enforce({"a": [1, 2]}, s).ok
        assert not so.enforce({"a": [float("inf")]}, s).ok
        inp = {"a": [{"n": 1}]}
        r = so.enforce(inp, s)
        r.value["a"][0]["n"] = 9
        assert inp == {"a": [{"n": 1}]}


# A hostile dict key whose __str__/
# __repr__ raises must not break the never-raises contract (it reached sorted(
# key=str) and the _fmt f-string). enforce() must always return an EnforceResult.
def test_enforce_never_raises_on_hostile_dict_key():
    class _Hostile:
        def __hash__(self):
            return 0

        def __eq__(self, other):
            return self is other

        def __str__(self):
            raise RuntimeError("boom __str__")

        def __repr__(self):
            raise RuntimeError("boom __repr__")

    # 1) top-level strict — the hostile key is "unexpected" (sorted + _fmt path)
    r1 = so.enforce({_Hostile(): 1}, so.Schema({"x": (int, 0)}), mode="strict")
    assert r1.ok is False  # unexpected key flagged, no raise

    # 2) lenient — unexpected key dropped, still no raise
    r2 = so.enforce({_Hostile(): 1}, so.Schema({"x": (int, 0)}), mode="lenient")
    assert r2.ok is True

    # 3) typed-map dict[str, int] with a hostile key (_validate_map sorted path) —
    # the map validates values, not key types, so ok may be True; the contract
    # under test is that enforce RETURNS a result and never raises.
    r3 = so.enforce({"m": {_Hostile(): 1}}, so.Schema({"m": dict[str, int]}), mode="strict")
    assert r3.ok in (True, False)
