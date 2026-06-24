"""test_packaging.py — PEP-562 lazy submodule access and packaging contracts."""
from __future__ import annotations

import subprocess
import sys


def _run_fresh(code: str) -> str:
    """Run *code* in a fresh interpreter and return stripped stdout."""
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"
    return proc.stdout.strip()


def test_bare_import_does_not_eagerly_load_submodules():
    # The agent_shield package must not load its public submodules on a bare
    # import; eager loading would cause RuntimeWarning when the CLI modules are
    # later executed as __main__. Check in a fresh interpreter because pytest's
    # shared process already has many submodules imported.
    code = (
        "import sys\n"
        "import agent_shield\n"
        "lazy = getattr(agent_shield, '_LAZY_SUBMODULES', set())\n"
        "loaded = [k for k in sys.modules if k.startswith('agent_shield.') and k.split('.')[1] in lazy]\n"
        "print(len(loaded))\n"
    )
    assert _run_fresh(code) == "0"


def test_getattr_resolves_submodules_on_demand():
    # Use a fresh interpreter so no prior test has cached the submodule in
    # agent_shield.__dict__ or sys.modules.
    code = (
        "import sys\n"
        "import agent_shield\n"
        "assert 'agent_shield.bash_guard' not in sys.modules, 'submodule already cached'\n"
        "bg = agent_shield.bash_guard\n"
        "assert bg is sys.modules['agent_shield.bash_guard']\n"
        "import agent_shield.bash_guard as bg2\n"
        "assert bg is bg2\n"
        "print('ok')\n"
    )
    assert _run_fresh(code) == "ok"


def test_from_import_still_works_with_getattr():
    code = (
        "import sys\n"
        "from agent_shield import skill_vetting\n"
        "assert skill_vetting is sys.modules['agent_shield.skill_vetting']\n"
        "print('ok')\n"
    )
    assert _run_fresh(code) == "ok"


def test_star_import_does_not_eagerly_load_submodules():
    # ``from agent_shield import *`` must not eager-load the lazy submodules.
    code = (
        "from agent_shield import *\n"
        "import sys\n"
        "import agent_shield\n"
        "lazy = agent_shield._LAZY_SUBMODULES\n"
        "loaded = [k for k in sys.modules if k.startswith('agent_shield.') and k.split('.')[1] in lazy]\n"
        "print(len(loaded))\n"
    )
    assert _run_fresh(code) == "0"


def test_getattr_rejects_unknown_names():
    import agent_shield

    try:
        agent_shield.not_a_real_module
    except AttributeError:
        pass
    else:
        raise AssertionError("unknown attribute should raise AttributeError")
