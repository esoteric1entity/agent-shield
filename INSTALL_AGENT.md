# INSTALL_AGENT.md — Agent-Executed Install

> **Audience:** the AI agent your user pointed at this package ("install this").
> **For humans:** this file is the entire specification of what your agent will do.
> **Review before you run.** agent-shield is a security product; its install honors
> the same rules it enforces — nothing happens to your Python environment or your
> harness settings without your explicit consent at each step.

---

You are an agent installing **agent-shield 0.1.0a4** — a defensive overlay for AI
agents. The shipping surface (Layer 4) is two runtime guards, `bash_guard` and
`write_guard`, used as a Python library or as harness hooks. Execute the steps below
**in order**; never claim a step succeeded without checking its result.

## Step 0 — Consent

Tell the user what this install does: (1) installs the `agent-shield` Python package
into an environment they choose; (2) **optionally** wires the guards into their
harness as PreToolUse hooks — which means editing their harness settings file;
(3) runs a verification smoke test. **Wait for explicit confirmation.**

## Step 1 — Detect

Probe (read-only) and report:

1. **Python:** `python3 --version` / `python --version` — 3.11+ required (per `pyproject.toml`). Identify
   the environment (venv? system? pipx available?). Prefer a venv or pipx;
   PEP 668-managed system Pythons will refuse a bare pip install.
2. **Harness:** Claude Code (`~/.claude/` exists)? OpenClaw? Other? Hooks wiring
   (Step 3) currently targets Claude Code; other harnesses use the library/CLI surface.
3. **Existing install:** `pip show agent-shield` — if present, this is an upgrade.

## Step 2 — Install the package

Use the first available source, in this order:

```bash
pip install git+https://github.com/esoteric1entity/agent-shield.git # from the repo (works today)
pip install <package-dir>                                           # local source (clone/checkout)
# pip install agent-shield                                          # PyPI — not yet published
# No prebuilt wheel ships in the repo; to build one: `python -m build` then
# `pip install dist/agent_shield-*.whl`.
```

Confirm the installed version matches the source: `python -c "import agent_shield; print(agent_shield.__version__)"` → `0.1.0a4` (the value is read from package metadata, so it always tracks `pyproject.toml`).

## Step 3 — Wire the hooks (Claude Code only; consent required)

The hooks file is **user-owned and security-sensitive** (`~/.claude/settings.json`,
or `.claude/settings.json` for project scope — ask which the user wants).

1. Read the current settings file (if any) and **append** the two `PreToolUse`
   entries from `examples/claude-code-settings.example.json` to the existing
   `hooks.PreToolUse` array — creating `hooks` / `hooks.PreToolUse` only if
   absent. Do **not** replace the `hooks` object or the array. The two entries:
   `Bash` → `python -m agent_shield.bash_guard`, `Write|Edit|MultiEdit` →
   `python -m agent_shield.write_guard`. It is normal for the same matcher to
   appear more than once; Claude Code runs all matching hooks and deduplicates
   byte-identical commands.
2. **Show the user the exact before/after diff. Do not write without approval.**
3. Never remove or alter existing hooks — merge only. If a conflicting matcher
   exists, show it and let the user decide.
4. The user must restart their Claude Code session for hooks to load.

For OpenClaw and other harnesses: skip this step — integrate via the library API
(`bash_guard.check_command()`, `write_guard.check_path()`) or pipe JSON to the CLI
(see `examples/hook-cli-pipe.example.sh`). Deep harness-native wiring is on the roadmap.

## Step 4 — Verify

Run the contract smoke (route test payloads through stdin — never execute them):

```bash
echo '{"tool_input":{"command":"rm -rf /"}}' | python -m agent_shield.bash_guard
# expect JSON with "permissionDecision": "deny"

echo '{"tool_input":{"command":"ls"}}' | python -m agent_shield.bash_guard
# expect EMPTY stdout (empty-stdout-for-allow is the CLI contract)
```

Optionally, with pytest available: `pytest <package-dir>/tests -q`
(the bash-subprocess parity cases auto-resolve a POSIX bash — Git-Bash/Cygwin on
Windows, native bash elsewhere — and skip cleanly if none is present, so the
full suite is safe to run anywhere; see the Tests section of `README.md`).

**If verification fails, report it plainly and stop — do not call the install done.**

## Step 5 — Record + report

Offer to write an install manifest (e.g. `~/.claude/agent-shield-manifest.json`):
package, version, install source, python environment, hooks wired (yes/no + scope),
timestamp. If declined, include the same facts in your final report instead.

Then summarize honestly: environment, version confirmed, hooks wired or not, smoke
results, and the restart reminder. Point the user at `SECURITY.md` (what the guards
do and do not protect against) and `examples/before-after.md`.

---

*Cross-references: `README.md` (quick start + API) · `SECURITY.md` (threat model +
disclosure) · `examples/` (settings wiring, library use, CLI pipe) ·
`CHANGELOG.md`.*
