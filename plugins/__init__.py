#!/usr/bin/env python3
# HackPilot core module
"""Plugin registry: additional open-source tools that complement the
built-in pipeline (exploitation/tools/*) without replacing it.

Each plugin is independently enabled via its own ENABLE_<NAME>_PLUGIN
env var, defaulting to false - with every plugin disabled, HackPilot
behaves exactly as it did before this module existed. Plugins reuse the
project's single ALLOWED_TARGETS allowlist (security.target_allowlist)
rather than a second, parallel scope variable.

Findings a plugin returns are plain dicts in the same shape
exploitation.tools.* runners already produce (title/target/source/
severity/evidence with a confirming_command) so they flow through the
existing findings_consolidator/report pipeline unchanged - there is no
separate plugin report path to keep in sync.
"""

import logging
import os
from typing import Any, Dict, List

from .base import Plugin, PluginContext, PluginResult

logger = logging.getLogger("hackpilot.plugins")

_REGISTRY: Dict[str, List[Plugin]] = {}


def register(plugin: Plugin) -> Plugin:
    _REGISTRY.setdefault(plugin.phase, []).append(plugin)
    return plugin


def _load_builtin_plugins() -> None:
    if _REGISTRY:
        return
    from .theharvester_plugin import TheHarvesterPlugin
    from .crtsh_plugin import CrtShPlugin
    from .nmap_vulners_plugin import NmapVulnersPlugin
    from .nikto_json_plugin import NiktoJsonPlugin
    from .wpscan_plugin import WPScanPlugin
    from .joomscan_plugin import JoomScanPlugin
    from .sqlmap_api_plugin import SqlmapApiPlugin

    for plugin_cls in (
        TheHarvesterPlugin, CrtShPlugin, NmapVulnersPlugin,
        NiktoJsonPlugin, WPScanPlugin, JoomScanPlugin, SqlmapApiPlugin,
    ):
        register(plugin_cls())


def run_phase_plugins(phase: str, ctx: PluginContext) -> List[Dict[str, Any]]:
    """Run every enabled, applicable plugin registered for `phase`, return
    their findings flattened into one list. Never raises - a plugin that
    fails is logged and skipped, same isolation discipline as the existing
    exploitation.tools.* runner call sites."""
    _load_builtin_plugins()
    findings: List[Dict[str, Any]] = []
    for plugin in _REGISTRY.get(phase, []):
        env_var = f"ENABLE_{plugin.name.upper()}_PLUGIN"
        if os.getenv(env_var, "false").lower() not in ("1", "true", "yes"):
            continue
        try:
            if not plugin.is_applicable(ctx):
                continue
        except Exception as e:
            logger.warning("Plugin %s is_applicable() failed: %s", plugin.name, e)
            continue

        try:
            result = plugin.run(ctx)
        except Exception as e:
            logger.warning("Plugin %s failed: %s", plugin.name, e)
            continue

        if result.errors:
            logger.warning("Plugin %s reported errors: %s", plugin.name, result.errors)
        findings.extend(result.findings)
    return findings
