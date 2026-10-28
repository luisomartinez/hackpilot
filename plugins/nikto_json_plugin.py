#!/usr/bin/env python3
# HackPilot core module
"""nikto with structured JSON output, run alongside (not instead of) the
existing phase3 nikto call. JSON parsing is far more reliable than the
"+"-prefixed stdout lines the existing call scrapes (that parser already
had to special-case nikto's own "[FAIL] Unable to connect" notice this
session) - this plugin is the reliability upgrade, additive so the
already-debugged existing call is untouched."""

import logging
import os
import tempfile
from datetime import datetime
from typing import Any, Dict, List

from .base import Plugin, PluginContext, PluginResult
from exploitation.tools._common import cleanup, read_json_file

logger = logging.getLogger("hackpilot.plugins.nikto_json")


class NiktoJsonPlugin(Plugin):
    name = "nikto_json"
    phase = "assessment"

    def is_applicable(self, ctx: PluginContext) -> bool:
        return ctx.has_web_service

    def run(self, ctx: PluginContext) -> PluginResult:
        started = datetime.utcnow()
        fd, out_path = tempfile.mkstemp(suffix=".nikto.json")
        os.close(fd)
        os.remove(out_path)  # nikto refuses to overwrite an existing file

        args = ["nikto", "-h", ctx.target, "-o", out_path, "-Format", "json", "-maxtime", "60s"]
        result = ctx.tool_manager.run_command(args, timeout=90)
        data = read_json_file(out_path)
        cleanup(out_path)

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        if not data:
            if not result.get("success"):
                errors.append((result.get("stderr") or "").strip() or "nikto JSON run produced no output")
        else:
            cmd_str = " ".join(args)
            entries = data.get("vulnerabilities") if isinstance(data, dict) else data
            for entry in entries or []:
                msg = entry.get("msg") or entry.get("message") or ""
                if not msg:
                    continue
                findings.append({
                    "title": f"nikto (json): {msg[:120]}",
                    "target": entry.get("url") or ctx.target,
                    "source": "nikto_json",
                    "severity": "info",
                    "evidence": {**entry, "confirming_command": cmd_str},
                })

        return PluginResult(
            tool=self.name, phase=self.phase, command=" ".join(args),
            started_at=started, finished_at=datetime.utcnow(),
            findings=findings, errors=errors,
        )
