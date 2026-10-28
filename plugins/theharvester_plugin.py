#!/usr/bin/env python3
# HackPilot core module
"""theHarvester (https://github.com/laramies/theHarvester) - passive OSINT
recon across public sources. Complements subfinder/amass (DNS-only) with
emails, hosts and IPs theHarvester's own source set surfaces."""

import logging
import os
import tempfile
from datetime import datetime
from typing import Any, Dict, List

from .base import Plugin, PluginContext, PluginResult
from exploitation.tools._common import cleanup, read_json_file

logger = logging.getLogger("hackpilot.plugins.theharvester")


class TheHarvesterPlugin(Plugin):
    name = "theharvester"
    phase = "reconnaissance"

    def is_applicable(self, ctx: PluginContext) -> bool:
        # Same reasoning as subfinder/amass: there is no domain to harvest
        # OSINT for against a bare IP target.
        import ipaddress
        try:
            ipaddress.ip_address(ctx.scan_host)
            return False
        except ValueError:
            return bool(ctx.scan_host)

    def run(self, ctx: PluginContext) -> PluginResult:
        started = datetime.utcnow()
        fd, out_base = tempfile.mkstemp(suffix=".theharvester")
        os.close(fd)
        os.remove(out_base)  # theHarvester writes <out_base>.json itself
        json_path = f"{out_base}.json"

        args = [
            "theHarvester", "-d", ctx.scan_host,
            "-b", "bing,crtsh,dnsdumpster", "-l", "500", "-f", out_base,
        ]
        result = ctx.tool_manager.run_command(args, timeout=300)
        data = read_json_file(json_path)
        cleanup(json_path, f"{out_base}.xml")

        errors = []
        findings: List[Dict[str, Any]] = []
        if not data:
            if not result.get("success"):
                errors.append((result.get("stderr") or "").strip() or "theHarvester produced no output")
        else:
            cmd_str = " ".join(args)
            for email in data.get("emails") or []:
                findings.append(self._finding("Email discovered", email, "info", cmd_str))
            for host in data.get("hosts") or []:
                # theHarvester's "hosts" entries are "subdomain:ip" or bare subdomain.
                subdomain = host.split(":", 1)[0]
                findings.append(self._finding(f"Subdomain discovered: {subdomain}", subdomain, "info", cmd_str))
            for ip in data.get("ips") or data.get("ip_addresses") or []:
                findings.append(self._finding("IP discovered", ip, "info", cmd_str))

        return PluginResult(
            tool=self.name, phase=self.phase, command=" ".join(args),
            started_at=started, finished_at=datetime.utcnow(),
            raw_output_path=json_path, findings=findings, errors=errors,
        )

    @staticmethod
    def _finding(title: str, target: str, severity: str, command: str) -> Dict[str, Any]:
        return {
            "title": title, "target": target, "source": "theharvester",
            "severity": severity, "evidence": {"confirming_command": command},
        }
