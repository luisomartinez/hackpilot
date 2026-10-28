#!/usr/bin/env python3
# HackPilot core module
"""nmap --script vulners - maps detected service versions to known CVEs
via vulners.com's NSE database. Complements the existing phase2 nmap -sV
call (which only gets banners) with an actual CVE list, still read-only."""

import logging
import os
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, List

from .base import Plugin, PluginContext, PluginResult
from exploitation.tools._common import cleanup

logger = logging.getLogger("hackpilot.plugins.nmap_vulners")


class NmapVulnersPlugin(Plugin):
    name = "nmap_vulners"
    phase = "scanning"

    def run(self, ctx: PluginContext) -> PluginResult:
        started = datetime.utcnow()
        fd, out_path = tempfile.mkstemp(suffix=".vulners.xml")
        os.close(fd)

        args = [
            "nmap", "-sV", "--script", "vulners", "--script-args", "mincvss=7.0",
            "-oX", out_path, ctx.scan_host,
        ]
        result = ctx.tool_manager.run_command(args, timeout=300)
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        try:
            tree = ET.parse(out_path)
            findings = self._parse(tree, ctx.scan_host, " ".join(args))
        except (ET.ParseError, FileNotFoundError) as e:
            errors.append(
                (result.get("stderr") or "").strip() or f"could not parse nmap XML output: {e}"
            )
        finally:
            cleanup(out_path)

        return PluginResult(
            tool=self.name, phase=self.phase, command=" ".join(args),
            started_at=started, finished_at=datetime.utcnow(),
            findings=findings, errors=errors,
        )

    @staticmethod
    def _parse(tree: ET.ElementTree, host: str, command: str) -> List[Dict[str, Any]]:
        findings = []
        for port_el in tree.findall(".//port"):
            port_id = port_el.get("portid", "")
            for script in port_el.findall("script[@id='vulners']"):
                for table in script.findall(".//table"):
                    cve_elem = table.find("elem[@key='id']")
                    cvss_elem = table.find("elem[@key='cvss']")
                    if cve_elem is None or not (cve_elem.text or "").startswith("CVE-"):
                        continue
                    cve_id = cve_elem.text.strip()
                    cvss = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else None
                    severity = "critical" if (cvss or 0) >= 9 else "high" if (cvss or 0) >= 7 else "medium"
                    findings.append({
                        "title": f"{cve_id} (vulners, port {port_id})",
                        "target": f"{host}:{port_id}",
                        "source": "nmap_vulners",
                        "severity": severity,
                        "evidence": {"cve_id": cve_id, "cvss": cvss, "confirming_command": command},
                    })
        return findings
