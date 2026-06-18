"""Shared cross-platform POSIX-bash resolution for the .sh parity harnesses.

Imported by both ``conftest.py`` (the pytest ``bash_exe`` fixture) and
``run_equivalence_test.py`` (the standalone head-to-head runner). Pure stdlib —
deliberately no pytest dependency — so the standalone runner can use it too.

Why this exists
---------------
The parity harnesses shell out to bash to run the .sh mirrors and compare their
decisions against the Python ports. On Windows, ``subprocess.run(["bash", …])``
does NOT honour PATH order the way an interactive shell does: Win32
CreateProcess searches the System32 directory *before* PATH, so a bare "bash"
resolves to ``C:\\Windows\\System32\\bash.exe`` — the **WSL launcher** — whenever
the WSL optional feature is installed.

Driven from a native-Windows Python with piped stdin and a non-translatable
working directory (e.g. an F:\\ drive with spaces), WSL bash hangs until the
caller's timeout fires. (The earlier docs blamed "UNC paths / Cygwin piped
stdin" — a misdiagnosis. Git-Bash with piped stdin works correctly in ~1s. The
sole cause is which bash.exe CreateProcess selects.)

Fix: resolve a real POSIX bash (Git-Bash / Cygwin / native) explicitly and pass
its absolute path to subprocess, never the System32 WSL stub or the Microsoft
Store alias. On Linux/macOS/WSL-as-CI this returns /usr/bin/bash and the whole
story is a no-op.

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""
from __future__ import annotations

import functools
import os
import shutil
import subprocess

# Bash executables we must never select: the WSL launcher (hangs from
# native-Windows Python piped stdin) and the Microsoft Store alias stub.
_BASH_DENY_FRAGMENTS = ("\\windows\\system32\\", "\\windowsapps\\")

NO_BASH_REASON = (
    "no usable POSIX bash found for the .sh parity tests "
    "(Git-Bash / Cygwin / native bash). The Windows WSL launcher "
    "(System32\\bash.exe) is intentionally excluded — it hangs on piped stdin "
    "from native-Windows Python. Install Git for Windows, or set "
    "AGENT_SHIELD_TEST_BASH to a usable bash.exe."
)


def _candidate_bash_paths() -> list[str]:
    """Ordered, de-duplicated list of plausible POSIX-bash executables."""
    candidates: list[str] = []

    # 1. Explicit override always wins (escape hatch for unusual installs / CI).
    override = os.environ.get("AGENT_SHIELD_TEST_BASH")
    if override:
        candidates.append(override)

    # 2. shutil.which() searches PATH in order — NOT System32-first like
    #    CreateProcess — so on a dev box with Git on PATH this returns Git-Bash.
    which = shutil.which("bash")
    if which:
        candidates.append(which)

    # 3. Known Git-Bash / Cygwin install locations, for when bash isn't on PATH.
    if os.name == "nt":
        candidates += [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
            r"C:\cygwin64\bin\bash.exe",
            r"C:\cygwin\bin\bash.exe",
        ]

    seen: set[str] = set()
    out: list[str] = []
    for cand in candidates:
        if not cand:
            continue
        key = os.path.normcase(os.path.abspath(cand))
        if key in seen:
            continue
        seen.add(key)
        if not os.path.isfile(cand):
            continue
        low = cand.replace("/", "\\").lower()
        if any(frag in low for frag in _BASH_DENY_FRAGMENTS):
            continue
        out.append(cand)
    return out


def _bash_handles_piped_stdin(bash_exe: str) -> bool:
    """Confirm this bash round-trips piped stdin without hanging.

    Mirrors the exact failure mode (native-Windows Python -> bash, stdin via a
    pipe). A hung WSL stub that somehow slipped past the path filter is caught
    here as a timeout and rejected, turning a whole-suite hang into a clean skip.
    """
    try:
        result = subprocess.run(
            [bash_exe, "-c", "cat"],
            input="agent-shield-bash-probe",
            capture_output=True,
            encoding="utf-8",
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "agent-shield-bash-probe"


@functools.lru_cache(maxsize=1)
def resolve_posix_bash() -> str | None:
    """Absolute path to a POSIX bash usable for the .sh parity tests, or None.

    Cached: the probe subprocess runs at most once per process.
    """
    for cand in _candidate_bash_paths():
        if _bash_handles_piped_stdin(cand):
            return cand
    return None
