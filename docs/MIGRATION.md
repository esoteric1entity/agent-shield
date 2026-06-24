# Migration Guide — Legacy Earlier-Alpha Wiring to Canonical Wiring

If you wired agent-shield during an earlier alpha (before the canonical `matcher` +
nested `hooks` shape was established), your harness settings may use a legacy shape
that **no longer works**. This guide explains what changed, why, and how to migrate to
the current canonical wiring.

> ⚠️ **Security warning for Claude Code users:** legacy alpha wiring used
> `python -m agent_shield.adapters.claude_code` as the guard command. That module has
> **no `__main__` CLI surface**, so every matching tool call failed silently into the
> harness and your settings were **not actually protected**. If you wired during an
> earlier alpha, migrate immediately.
>
> This shape appeared only in early internal/alpha builds. If you installed from the
> public repo or PyPI you likely do not need this guide — but if you copied an old
> snippet that uses `hookEventName` / `toolNamePattern`, read on.

---

## Claude Code

### Legacy shape (earlier alphas before Phase P3)

Early internal alphas wrote entries that look like this:

Bash:

```json
{
  "hookEventName": "PreToolUse",
  "toolNamePattern": "Bash",
  "command": "python -m agent_shield.adapters.claude_code"
}
```

Write/Edit:

```json
{
  "hookEventName": "PreToolUse",
  "toolNamePattern": "Write|Edit|MultiEdit",
  "command": "python -m agent_shield.adapters.claude_code"
}
```

### Why it changed

- The command target (`python -m agent_shield.adapters.claude_code`) has no CLI entry
  point, so the hook produced an error on every matching call and enforcement did not
  happen.
- Claude Code's canonical hook shape uses `matcher` + a nested `hooks` array, not the
  flat `hookEventName`/`toolNamePattern`/`command` shape.

### Canonical shape (current)

Bash:

```json
{
  "matcher": "Bash",
  "hooks": [
    {
      "type": "command",
      "command": "python -m agent_shield.bash_guard",
      "timeout": 5
    }
  ]
}
```

Write/Edit:

```json
{
  "matcher": "Write|Edit|MultiEdit",
  "hooks": [
    {
      "type": "command",
      "command": "python -m agent_shield.write_guard",
      "timeout": 5
    }
  ]
}
```

### Migration steps

1. Disable the old wiring:
   ```bash
   agent-shield-plugin disable
   # or, for project-level settings:
   agent-shield-plugin --project ./myproj disable
   ```
   `disable` removes **both** the canonical entries and any legacy entries that still
   point at the old `python -m agent_shield.adapters.claude_code` command — including
   ones with extra keys or a different `toolNamePattern`. If you modified the command
   string itself (e.g., added arguments) or the CLI is unavailable, use the manual
   fallback below to remove every entry that contains `hookEventName` or the old
   command.

2. Enable the canonical wiring:
   ```bash
   agent-shield-plugin enable
   # or, for project-level settings:
   agent-shield-plugin --project ./myproj enable
   ```

3. Restart Claude Code so it reloads `settings.json`.

### Manual fallback (if the CLI is unavailable)

Edit `~/.claude/settings.json` (or the project `.claude/settings.json`) directly:

1. Remove every entry that contains `"hookEventName"`, `"toolNamePattern"`, or
   `"python -m agent_shield.adapters.claude_code"`.
2. Preserve unrelated hooks and any other top-level keys.
3. Append the two canonical entries from
   [`examples/claude-code-settings.example.json`](../examples/claude-code-settings.example.json).
4. Validate the JSON before saving.

See [`INSTALL_AGENT.md`](../INSTALL_AGENT.md) Step 6 for the canonical uninstall flow;
use the "Manual fallback" steps above specifically for legacy `hookEventName` cleanup.

---

## OpenClaw

### Legacy shape

The legacy companion plugin used a bare export that OpenClaw's current loaders silently
skip:

```typescript
export const hooks = {
  before_tool_call: { priority: 100, handler },
};
```

Because current loaders look for a plugin-SDK `register`/`activate` export, this shape
loads without error but **does not register the hook** — the guard is a silent no-op.

### Canonical shape (current)

The shipped plugin uses the plugin-SDK entry contract:

```typescript
export default definePluginEntry({
  id: "agent-shield",
  register(api) {
    api.on("before_tool_call", handler, { priority: 100 });
  },
});
```

### Migration steps

1. Uninstall the old companion plugin using the mechanism your OpenClaw version
   documents. The exact command is version-specific; do not rely on a copy-pasted
   snippet unless you have verified it locally.
2. Locate the new plugin directory shipped inside the installed package. On Linux/macOS
   (Git Bash / WSL):
   ```bash
   DIR=$(python -c "import agent_shield, pathlib; print(pathlib.Path(agent_shield.__file__).parent / 'adapters' / 'openclaw_plugin')")
   ```
   On Windows PowerShell the same one-liner works with double-quoted outer quotes:
   ```powershell
   $DIR = python -c "import agent_shield, pathlib; print(pathlib.Path(agent_shield.__file__).parent / 'adapters' / 'openclaw_plugin')"
   ```
3. Install the new plugin directory. The verified recipe — including the gateway
   version requirement and any install flags — lives in
   [`docs/adapter_status.md`](adapter_status.md).
4. **Restart the gateway.** Hot-reload may update `plugins list` but it does not
   re-register plugin hooks.

> ⚠️ **Transient window:** between uninstalling the old plugin and completing the
> install+restart, the gateway runs unprotected. Complete the sequence promptly and
> avoid relying on the guard during that window.
