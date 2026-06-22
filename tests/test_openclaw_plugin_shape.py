"""
test_openclaw_plugin_shape.py — pin the OpenClaw companion plugin's install contract
====================================================================================

Why this suite exists: the OpenClaw companion plugin once shipped the *legacy*
``export const hooks = {...}`` shape. Current OpenClaw gateways load that file
but look for a ``register``/``activate`` export — so the hook never registered and
the guard was a silent no-op (loads green, enforces nothing). It was caught only by
a live enforcement test (2026-06-20), not by the suite.

These tests are the regression pin so the no-op cannot come back, and so the exact
install contract proven to enforce live (the ``openclaw.extensions`` entry + the
plugin id) cannot silently drift:

  1. The plugin ships as a clean, directory-installable unit (index.ts + the two
     manifests OpenClaw needs), so ``openclaw plugins install <dir>`` works with no
     hand-authoring.
  2. ``index.ts`` registers through the plugin-SDK entry contract
     (``definePluginEntry`` + ``register(api)`` + ``api.on("before_tool_call", ...)``)
     and does NOT use the legacy bare ``export const hooks`` registration.
  3. ``package.json`` declares ``openclaw.extensions: ["./index.ts"]`` — the key whose
     absence made the install fall back to the hook-pack path and error.
  4. ``openclaw.plugin.json`` declares the plugin id.

Author: esoteric1entity, assisted by Claude Code & OpenClaw
License: Apache-2.0
"""
from __future__ import annotations

import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_DIR = _ROOT / "agent_shield" / "adapters" / "openclaw_plugin"
INDEX_TS = PLUGIN_DIR / "index.ts"
PLUGIN_JSON = PLUGIN_DIR / "openclaw.plugin.json"
PACKAGE_JSON = PLUGIN_DIR / "package.json"

# A faithful sample of the export shape that shipped the silent no-op — kept here as a
# permanent negative control so the predicate below is proven to reject it on every run.
_LEGACY_NOOP_SAMPLE = """
import { spawnSync } from "node:child_process";
const handler = (event) => ({});
export const hooks = {
  before_tool_call: { priority: 100, handler },
};
"""


def _registers_via_plugin_sdk(ts: str) -> bool:
    """True iff the source registers through the plugin-SDK entry contract rather than
    the legacy bare ``export const hooks`` shape that current loaders silently skip."""
    has_modern = (
        "definePluginEntry" in ts
        and "register(" in ts
        and "api.on(" in ts
        and "before_tool_call" in ts
    )
    uses_legacy = "export const hooks" in ts
    return has_modern and not uses_legacy


def test_plugin_ships_as_clean_installable_directory():
    """index.ts + both manifests live together so `openclaw plugins install <dir>` works."""
    assert PLUGIN_DIR.is_dir(), f"plugin dir missing: {PLUGIN_DIR}"
    assert INDEX_TS.is_file(), f"index.ts missing: {INDEX_TS}"
    assert PLUGIN_JSON.is_file(), f"openclaw.plugin.json missing: {PLUGIN_JSON}"
    assert PACKAGE_JSON.is_file(), f"package.json missing: {PACKAGE_JSON}"


def test_index_registers_via_plugin_sdk_not_legacy_hooks():
    """The shipped entry must use definePluginEntry/register/api.on — not the no-op shape."""
    assert _registers_via_plugin_sdk(INDEX_TS.read_text(encoding="utf-8"))


def test_legacy_hooks_export_is_rejected():
    """Negative control: the predicate must flag the historical no-op shape."""
    assert not _registers_via_plugin_sdk(_LEGACY_NOOP_SAMPLE)


def test_package_json_declares_openclaw_extensions_entry():
    """The `openclaw.extensions` key is required; without it the install errors."""
    data = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    assert data.get("type") == "module"
    assert data.get("openclaw", {}).get("extensions") == ["./index.ts"]


def test_plugin_manifest_declares_id():
    data = json.loads(PLUGIN_JSON.read_text(encoding="utf-8"))
    assert data.get("id") == "agent-shield"
