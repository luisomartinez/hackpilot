#!/usr/bin/env python3
# HackPilot core module
"""crt.sh - passive certificate-transparency log lookup. No API key, no
tool to install; a single HTTP GET. Purely passive - never touches the
target itself, only a public CT-log aggregator."""

import ipaddress
import logging
from datetime import datetime
from typing import Any, Dict, List

from .base import Plugin, PluginContext, PluginResult

logger = logging.getLogger("hackpilot.plugins.crtsh")


class CrtShPlugin(Plugin):
    name = "crtsh"
    phase = "reconnaissance"

    def is_applicable(self, ctx: PluginContext) -> bool:
        try:
            ipaddress.ip_address(ctx.scan_host)
            return False  # certificate transparency logs are per-domain, not per-IP
        except ValueError:
            return bool(ctx.scan_host)

    def run(self, ctx: PluginContext) -> PluginResult:
        import requests

        started = datetime.utcnow()
        url = f"https://crt.sh/?q=%25.{ctx.scan_host}&output=json"
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            records = resp.json()
        except Exception as e:
            errors.append(str(e))
            records = []

        subdomains = {r.get("name_value", "").strip().lower() for r in records if r.get("name_value")}
        # Each name_value entry can itself be newline-separated (multi-SAN certs).
        flattened = set()
        for entry in subdomains:
            flattened.update(line.strip() for line in entry.splitlines() if line.strip())

        for subdomain in sorted(flattened):
            if subdomain.startswith("*."):
                subdomain = subdomain[2:]
            findings.append({
                "title": f"Subdomain discovered: {subdomain}",
                "target": subdomain, "source": "crtsh", "severity": "info",
                "evidence": {"confirming_command": url},
            })

        return PluginResult(
            tool=self.name, phase=self.phase, command=url,
            started_at=started, finished_at=datetime.utcnow(),
            findings=findings, errors=errors,
        )
