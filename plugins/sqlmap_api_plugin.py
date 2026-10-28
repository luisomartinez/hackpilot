#!/usr/bin/env python3
# HackPilot core module
"""sqlmap's REST-JSON API (sqlmapapi.py), as an alternative to the
existing CLI-based exploitation.tools.sqlmap_runner: structured JSON
status/data instead of regexing CLI stdout, for the same confirm-and-stop
policy already enforced there.

Hard restriction (same RoE as sqlmap_runner.py): the scan options sent to
the API must never include an option that extracts data or spawns a
shell/OS command. _assert_safe_options() enforces this independent of
whatever this file's OPTIONS dict says, same defense-in-depth pattern as
sqlmap_runner.py's _assert_safe_args().

NOTE: not yet exercised against a live target in this environment - the
exact binary name (sqlmapapi.py vs sqlmapapi vs sqlmap --api, depending
on packaging) needs confirming against the real Kali sqlmap package
before this plugin is enabled by default. Ship disabled
(ENABLE_SQLMAP_API_PLUGIN unset) until that's verified live, the same way
testssl's binary name turned out to differ from its apt package name.
"""

import logging
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import Plugin, PluginContext, PluginResult

logger = logging.getLogger("hackpilot.plugins.sqlmap_api")

_FORBIDDEN_OPTION_KEYS = (
    "osShell", "osPwn", "osSmb", "regRead", "regAdd", "regDel",
    "dumpAll", "fileRead", "fileWrite", "fileDest", "sqlShell",
)

_SAFE_OPTIONS = {
    "level": 5,
    "risk": 3,
    "technique": "BEUST",
    "batch": True,
    "getDbs": True,  # same stopping point as the CLI runner's --dbs
}


def _assert_safe_options(options: Dict[str, Any]) -> None:
    for key in _FORBIDDEN_OPTION_KEYS:
        if options.get(key):
            raise AssertionError(f"Refusing to start sqlmap API scan with forbidden option {key!r}")


class SqlmapApiPlugin(Plugin):
    name = "sqlmap_api"
    phase = "exploitation"
    PORT = 8775

    def is_applicable(self, ctx: PluginContext) -> bool:
        return "?" in ctx.target

    def run(self, ctx: PluginContext) -> PluginResult:
        import requests

        started = datetime.utcnow()
        base = f"http://127.0.0.1:{self.PORT}"
        server_proc: Optional[subprocess.Popen] = None
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        command_repr = f"sqlmapapi.py -s -p {self.PORT}"

        try:
            server_proc = subprocess.Popen(
                ["sqlmapapi.py", "-s", "-p", str(self.PORT)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if not self._wait_for_server(base, requests):
                errors.append("sqlmap API server did not come up in time")
                return PluginResult(tool=self.name, phase=self.phase, command=command_repr,
                                     started_at=started, finished_at=datetime.utcnow(), errors=errors)

            task_id = requests.post(f"{base}/task/new", timeout=10).json().get("taskid")
            if not task_id:
                errors.append("sqlmap API did not return a task id")
                return PluginResult(tool=self.name, phase=self.phase, command=command_repr,
                                     started_at=started, finished_at=datetime.utcnow(), errors=errors)

            options = {**_SAFE_OPTIONS, "url": ctx.target}
            _assert_safe_options(options)
            requests.post(f"{base}/option/{task_id}/set", json=options, timeout=10)
            requests.post(f"{base}/scan/{task_id}/start", json={"url": ctx.target}, timeout=10)

            deadline = time.time() + 900
            while time.time() < deadline:
                status = requests.get(f"{base}/scan/{task_id}/status", timeout=10).json()
                if status.get("status") == "terminated":
                    break
                time.sleep(3)

            data = requests.get(f"{base}/scan/{task_id}/data", timeout=10).json().get("data") or []
            findings = self._parse_data(data, ctx.target, command_repr)
            requests.get(f"{base}/task/{task_id}/delete", timeout=10)

        except Exception as e:
            errors.append(str(e))
        finally:
            if server_proc is not None:
                server_proc.kill()
                server_proc.wait(timeout=10)

        return PluginResult(
            tool=self.name, phase=self.phase, command=command_repr,
            started_at=started, finished_at=datetime.utcnow(),
            findings=findings, errors=errors,
        )

    @staticmethod
    def _wait_for_server(base: str, requests_module, attempts: int = 10) -> bool:
        for _ in range(attempts):
            try:
                if requests_module.get(base, timeout=2).status_code < 500:
                    return True
            except Exception:
                time.sleep(1)
        return False

    @staticmethod
    def _parse_data(data: List[Dict[str, Any]], target: str, command: str) -> List[Dict[str, Any]]:
        """sqlmap API /scan/<id>/data entries use a numeric 'type' field:
        0=target info, 1=technique(s), 2=DBMS fingerprint, others carry the
        dumped database/table names for getDbs. Values are only ever names
        confirmed vulnerable + enumerated database names - never row data,
        matching sqlmap_runner.py's existing stopping point."""
        if not data:
            return []
        techniques = dbms = None
        db_names: List[str] = []
        for entry in data:
            entry_type = entry.get("type")
            value = entry.get("value")
            if entry_type == 1:
                techniques = value
            elif entry_type == 2:
                dbms = value
            elif isinstance(value, list):
                db_names = value

        if not (techniques or dbms or db_names):
            return []
        return [{
            "title": "SQL Injection confirmed (sqlmap API)",
            "target": target, "source": "sqlmap_api", "severity": "critical",
            "evidence": {
                "dbms_fingerprint": dbms, "techniques": techniques,
                "databases_enumerated": db_names, "extraction_not_executed": True,
                "confirming_command": command,
            },
        }]
