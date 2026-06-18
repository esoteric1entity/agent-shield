# `agent-shield` examples

Worked examples for the three most common integration patterns.

## Files

| File | What it shows |
|---|---|
| [`claude-code-settings.example.json`](claude-code-settings.example.json) | Drop-in `~/.claude/settings.json` snippet that wires `bash_guard` + `write_guard` into Claude Code's PreToolUse hook chain |
| [`library-use.example.py`](library-use.example.py) | Importing `bash_guard` / `write_guard` from Python; inspecting `GuardResult`; composing custom decisions |
| [`hook-cli-pipe.example.sh`](hook-cli-pipe.example.sh) | Running the CLI directly via stdin / stdout — useful for testing or for wiring into non-Claude harnesses |
| [`before-after.md`](before-after.md) | What changes for the agent + the user when the shield is installed |

---

## Quick start: drop the JSON

```bash
# Back up your existing settings
cp ~/.claude/settings.json ~/.claude/settings.json.bak

# Merge the example into your settings (manually or via a JSON tool)
# See claude-code-settings.example.json for the exact structure

# Restart Claude Code — it picks up the new hooks on next session
```

Verify it's wired by trying a known-deny command:

```bash
# In Claude Code, ask the agent to run:
rm -rf /

# Expected: hook intercepts → "permissionDecision: deny" → command does not run
```

If the hook doesn't fire, check `~/.claude/logs/` for hook-load errors and confirm `python -m agent_shield.bash_guard` works standalone.

## What's NOT in examples

- **Configuration of pattern lists** — patterns are hardcoded in `agent_shield/{bash,write}_guard.py` for v0.1. A future release will add `agent_shield/patterns.toml` for user-extensible rules. Until then, fork the package to add custom patterns.
- **Custom audit-log destinations** — the hook output is what Claude Code logs; routing the JSON elsewhere is a layer-6 concern (not yet shipping).
- **Cross-machine policy sync** — a single agent-shield install protects one host. Cross-host policy is out of scope.

---

*A PDuk Brainworks project · Apache-2.0 · © 2026 esoteric1entity*
