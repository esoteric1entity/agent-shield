"""Release A (G5): the supported-Python floor is 3.11 (keeps tomllib in stdlib)."""
import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _meta() -> dict:
    with PYPROJECT.open("rb") as f:
        return tomllib.load(f)


def test_requires_python_floor_is_3_11():
    assert _meta()["project"]["requires-python"] == ">=3.11"


def test_classifiers_include_3_11_through_3_14():
    classifiers = _meta()["project"]["classifiers"]
    for v in ("3.11", "3.12", "3.13", "3.14"):
        assert f"Programming Language :: Python :: {v}" in classifiers
