#!/usr/bin/env python3
# HackPilot core module
"""JoomScan - only runs when Joomla is detected. JoomScan has no JSON
output mode, so this parses its stdout for CVE references and its own
"[++] Vulnerability" markers - a small, tolerant text parser rather than
a strict schema, since there isn't one."""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List

from .base import Plugin, PluginContext, PluginResult

logger = logging.getLogger("hackpilot.plugins.joomscan")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class JoomScanPlugin(Plugin):
    name = "joomscan"
    phase = "assessment"

    def is_applicable(self, ctx: PluginContext) -> bool:
        return ctx.has_web_service and any("joomla" in name.lower() for name in ctx.tech_names())

    def run(self, ctx: PluginContext) -> PluginResult:
        started = datetime.utcnow()
        url = ctx.target if "://" in ctx.target else f"http://{ctx.target}"
        args = ["joomscan", "-u", url]
        result = ctx.tool_manager.run_command(args, timeout=300)
        stdout = result.get("stdout", "")

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        if not result.get("success") and not stdout:
            errors.append((result.get("stderr") or "").strip() or "joomscan produced no output")
        else:
            cmd_str = " ".join(args)
            seen_cves = set()
            for line in stdout.splitlines():
                for cve in _CVE_RE.findall(line):
                    if cve in seen_cves:
                        continue
                    seen_cves.add(cve)
                    findings.append({
                        "title": f"JoomScan: possible {cve}",
                        "target": url, "source": "joomscan", "severity": "high",
                        "evidence": {"line": line.strip(), "confirming_command": cmd_str},
                    })
                if "[++]" in line and "vulnerab" in line.lower() and not _CVE_RE.search(line):
                    findings.append({
                        "title": f"JoomScan: {line.strip().lstrip('[+] ')[:120]}",
                        "target": url, "source": "joomscan", "severity": "medium",
                        "evidence": {"line": line.strip(), "confirming_command": cmd_str},
                    })

        return PluginResult(
            tool=self.name, phase=self.phase, command=" ".join(args),
            started_at=started, finished_at=datetime.utcnow(),
            findings=findings, errors=errors,
        )
