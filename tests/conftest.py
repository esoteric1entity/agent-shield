"""pytest conftest — agent_shield import path + cross-platform bash fixture.

The cross-platform bash resolution lives in ``_bash_resolve.py`` (pure stdlib,
no pytest) so the standalone ``run_equivalence_test.py`` runner can share it.
See that module for the full root-cause writeup (WSL ``bash.exe`` shim vs
Git-Bash on Windows). This file just adds the import path and the pytest
fixture wrapper.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).parent.resolve()
# Make agent_shield/ importable without pip install …
sys.path.insert(0, str(_HERE.parent))
# … and the sibling _bash_resolve module importable from this conftest.
sys.path.insert(0, str(_HERE))

from _bash_resolve import NO_BASH_REASON, resolve_posix_bash


@pytest.fixture(scope="session")
def bash_exe() -> str:
    """Session-scoped absolute path to a usable POSIX bash.

    Resolves Git-Bash/Cygwin (Windows) or native bash (Linux/macOS/WSL), never
    the Windows WSL launcher stub. Skips the requesting test cleanly — never
    hangs — when no usable bash exists.
    """
    exe = resolve_posix_bash()
    if exe is None:
        pytest.skip(NO_BASH_REASON)
    return exe
