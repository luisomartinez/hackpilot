#!/usr/bin/env python3
# HackPilot core module
"""WPScan - only runs when WordPress is actually detected (via whatweb's
tech fingerprint or a live /wp-json/ check), never unconditionally.
Enumeration only (vulnerable plugins + users) - no password brute-force,
no exploitation.

CLI flags (--url/--enumerate/--format/--output/--no-banner) confirmed
present via `wpscan --help` against the real Kali package this session,
but NOT run against an actual WordPress site - none of this session's
authorized targets run WordPress. The JSON schema _vulns_from() expects
(version/main_theme/plugins.<slug>, each with a "vulnerabilities" list)
is wpscan's documented output shape, not something exercised against
real positive data."""

import logging
import os
import tempfile
from datetime import datetime
from typing import Any, Dict, List

from .base import Plugin, PluginContext, PluginResult
from exploitation.tools._common import cleanup, read_json_file

logger = logging.getLogger("hackpilot.plugins.wpscan")


class WPScanPlugin(Plugin):
    name = "wpscan"
    phase = "assessment"

    def is_applicable(self, ctx: PluginContext) -> bool:
        if not ctx.has_web_service:
            return False
        if any("wordpress" in name.lower() for name in ctx.tech_names()):
            return True
        try:
            import requests
            url = ctx.target if "://" in ctx.target else f"http://{ctx.target}"
            resp = requests.get(url.rstrip("/") + "/wp-json/", timeout=10)
            return resp.status_code == 200 and "namespaces" in resp.text
        except Exception:
            return False

    def run(self, ctx: PluginContext) -> PluginResult:
        started = datetime.utcnow()
        fd, out_path = tempfile.mkstemp(suffix=".wpscan.json")
        os.close(fd)
        os.remove(out_path)

        url = ctx.target if "://" in ctx.target else f"http://{ctx.target}"
        args = [
            "wpscan", "--url", url, "--enumerate", "vp,u",
            "--format", "json", "-o", out_path, "--no-banner",
        ]
        api_token = os.getenv("WPSCAN_API_TOKEN")
        if api_token:
            args += ["--api-token", api_token]

        result = ctx.tool_manager.run_command(args, timeout=300)
        data = read_json_file(out_path)
        cleanup(out_path)

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        if not data:
            if not result.get("success"):
                errors.append((result.get("stderr") or "").strip() or "wpscan produced no output")
        else:
            cmd_str = " ".join(a if a != api_token else "***" for a in args)
            findings.extend(self._vulns_from(data.get("version"), url, "WordPress core", cmd_str))
            findings.extend(self._vulns_from(data.get("main_theme"), url, "active theme", cmd_str))
            for slug, plugin in (data.get("plugins") or {}).items():
                findings.extend(self._vulns_from(plugin, url, f"plugin '{slug}'", cmd_str))
            for user in (data.get("users") or {}).keys():
                findings.append({
                    "title": f"WordPress user enumerated: {user}",
                    "target": url, "source": "wpscan", "severity": "low",
                    "evidence": {"confirming_command": cmd_str},
                })

        return PluginResult(
            tool=self.name, phase=self.phase, command=" ".join(args),
            started_at=started, finished_at=datetime.utcnow(),
            findings=findings, errors=errors,
        )

    @staticmethod
    def _vulns_from(component: Any, url: str, label: str, command: str) -> List[Dict[str, Any]]:
        if not isinstance(component, dict):
            return []
        findings = []
        for vuln in component.get("vulnerabilities") or []:
            title = vuln.get("title") or "Unknown vulnerability"
            findings.append({
                "title": f"WPScan: {label} - {title}",
                "target": url, "source": "wpscan", "severity": "high",
                "evidence": {**vuln, "confirming_command": command},
            })
        return findings
