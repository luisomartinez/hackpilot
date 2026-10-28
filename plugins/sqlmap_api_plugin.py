#!/usr/bin/env python3
# HackPilot core module
"""sqlmap's REST-JSON API (sqlmapapi), as an alternative to the existing
CLI-based exploitation.tools.sqlmap_runner: structured JSON status/data
instead of regexing CLI stdout, for the same confirm-and-stop policy
already enforced there.

Hard restriction (same RoE as sqlmap_runner.py): the scan options sent to
the API must never include an option that extracts data or spawns a
shell/OS command. _assert_safe_options() enforces this independent of
whatever this file's OPTIONS dict says, same defense-in-depth pattern as
sqlmap_runner.py's _assert_safe_args().

Confirmed live against the real Kali sqlmap package (ad-hoc, against
Acunetix's public testphp.vulnweb.com test target - not a hypothetical):
- The apt package's own script is /usr/share/sqlmap/sqlmapapi.py, but the
  PATH symlink it installs is "sqlmapapi" (no ".py") - same kind of
  apt-package-name-vs-binary-name mismatch as testssl.sh/testssl.
- The server refuses to start without --username/--password (HTTP Basic
  Auth is mandatory, not optional, in this version) - a fresh random
  password is generated per run here, scoped to one ephemeral local
  server process, never reused or exposed.
- /task/new and /scan/<id>/{status,data}/task/<id>/delete are GET;
  /option/<id>/set and /scan/<id>/start are POST. (The task prompt that
  asked for this plugin got this wrong - it described /task/new as POST.)

NOT verified live: the exact /scan/<id>/data entry shape for a genuinely
confirmed-vulnerable target (the test run above completed cleanly but
found nothing, same honest result the CLI runner would have gotten
against a no-longer-vulnerable public test parameter) - _parse_data()'s
field mapping is sqlmap's documented schema, not something exercised
against positive data this session. Leave disabled until that's confirmed
too.
"""

import logging
import secrets
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
        username = "hackpilot"
        password = secrets.token_hex(16)
        auth = (username, password)
        server_proc: Optional[subprocess.Popen] = None
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        command_repr = f"sqlmapapi -s -p {self.PORT} --username {username} --password ***"

        try:
            server_proc = subprocess.Popen(
                ["sqlmapapi", "-s", "-p", str(self.PORT), "--username", username, "--password", password],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if not self._wait_for_server(base, requests, auth):
                errors.append("sqlmap API server did not come up in time")
                return PluginResult(tool=self.name, phase=self.phase, command=command_repr,
                                     started_at=started, finished_at=datetime.utcnow(), errors=errors)

            task_id = requests.get(f"{base}/task/new", auth=auth, timeout=10).json().get("taskid")
            if not task_id:
                errors.append("sqlmap API did not return a task id")
                return PluginResult(tool=self.name, phase=self.phase, command=command_repr,
                                     started_at=started, finished_at=datetime.utcnow(), errors=errors)

            options = {**_SAFE_OPTIONS}
            _assert_safe_options(options)
            requests.post(f"{base}/option/{task_id}/set", auth=auth, json=options, timeout=10)
            requests.post(f"{base}/scan/{task_id}/start", auth=auth, json={"url": ctx.target}, timeout=10)

            deadline = time.time() + 900
            while time.time() < deadline:
                status = requests.get(f"{base}/scan/{task_id}/status", auth=auth, timeout=10).json()
                if status.get("status") == "terminated":
                    break
                time.sleep(3)

            data = requests.get(f"{base}/scan/{task_id}/data", auth=auth, timeout=10).json().get("data") or []
            findings = self._parse_data(data, ctx.target, command_repr)
            requests.get(f"{base}/task/{task_id}/delete", auth=auth, timeout=10)

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
    def _wait_for_server(base: str, requests_module, auth, attempts: int = 10) -> bool:
        for _ in range(attempts):
            try:
                if requests_module.get(base, auth=auth, timeout=2).status_code < 500:
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
