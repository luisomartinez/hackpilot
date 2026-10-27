# HackPilot core module
"""Sprint 2: phase4_exploitation wiring - safe-mode default is unchanged,
the new ALLOWED_TARGETS gate blocks active tools even when both
exploitation flags are on, and the full active-mode orchestration
(ffuf -> sqlmap -> msf_check -> ffuf vhosts) persists consolidated
findings when the target is allowlisted.
"""

import json

from advance_hackpilot import EnterprisePentestingPhases, cancellation_registry, config


class FakeToolManager:
    def __init__(self, canned):
        self.canned = canned
        self.calls = []
        self.command_log = []

    def run_command(self, args, timeout=None):
        self.calls.append(list(args))
        spec = self.canned.get(args[0], {"success": True, "stdout": ""})
        if "json_file" in spec and "-o" in args:
            out_path = args[args.index("-o") + 1]
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(spec["json_file"], f)
        if "stdout_sequence" in spec:
            idx = sum(1 for c in self.calls if c[0] == args[0]) - 1
            seq = spec["stdout_sequence"]
            stdout = seq[min(idx, len(seq) - 1)]
            outcome = {"success": True, "stdout": stdout, "stderr": ""}
        else:
            outcome = {"success": spec.get("success", True), "stdout": spec.get("stdout", ""), "stderr": spec.get("stderr", "")}
        self.command_log.append({"command": " ".join(args), "success": outcome["success"]})
        return outcome


class FakeDB:
    def __init__(self):
        self.vulnerabilities = []
        self.phase_results = {}

    def create_phase_result(self, session_id, phase_name, phase_number, results, ai_analysis=None, tools_used=None, commands_used=None):
        rid = f"phase-{phase_number}"
        self.phase_results[rid] = {"tools_used": tools_used, "commands_used": commands_used, "status": "running"}
        return rid

    def update_phase_result(self, result_id, status, completed_at=None, results=None, ai_analysis=None, execution_time=None, commands_used=None):
        self.phase_results[result_id]["status"] = status
        self.phase_results[result_id]["results"] = results
        if commands_used is not None:
            self.phase_results[result_id]["commands_used"] = commands_used

    def create_vulnerability(self, session_id, phase, severity, title, description,
                              cvss_score=None, cvss_vector=None, proof_of_concept=None,
                              remediation=None, references=None, sources=None,
                              validated=False, confidence=None, evidence=None):
        self.vulnerabilities.append({"phase": phase, "severity": severity, "title": title})
        return f"vuln-{len(self.vulnerabilities)}"


def _phases(tool_manager, db, target="http://x.com"):
    phases = EnterprisePentestingPhases(
        session_id="s1", ai_engine=None, tool_manager=tool_manager,
        target_info={"target": target}, db=db, cache=None, processor=None,
        exploitation=None, zero_day_detector=None, compliance=None, report_generator=None,
    )
    return phases


def test_safe_mode_is_still_the_default_and_unchanged(monkeypatch):
    monkeypatch.setattr(config, "ENABLE_AUTO_EXPLOIT", False, raising=False)
    monkeypatch.setattr(config, "ENABLE_ADVANCED_EXPLOITATION", False, raising=False)
    tm = FakeToolManager({})
    db = FakeDB()
    result = _phases(tm, db).phase4_exploitation()

    assert result == {"success": True, "vulnerabilities": [], "risk_score": 0.0, "mode": "safe"}
    assert tm.calls == []  # nothing was ever shelled out to


def test_enabled_but_not_allowlisted_blocks_active_tools(monkeypatch):
    monkeypatch.setattr(config, "ENABLE_AUTO_EXPLOIT", True, raising=False)
    monkeypatch.setattr(config, "ENABLE_ADVANCED_EXPLOITATION", True, raising=False)
    monkeypatch.delenv("ALLOWED_TARGETS", raising=False)
    tm = FakeToolManager({})
    db = FakeDB()
    result = _phases(tm, db).phase4_exploitation()

    assert result["mode"] == "active"
    assert tm.calls == []
    assert any("Not Allowlisted" in v["title"] for v in db.vulnerabilities)


def test_enabled_and_allowlisted_runs_full_active_orchestration(monkeypatch):
    monkeypatch.setattr(config, "ENABLE_AUTO_EXPLOIT", True, raising=False)
    monkeypatch.setattr(config, "ENABLE_ADVANCED_EXPLOITATION", True, raising=False)
    monkeypatch.setenv("ALLOWED_TARGETS", "x.com")

    nuclei_record = {
        "template-id": "CVE-2021-9999", "info": {"name": "Some Vuln", "severity": "high"},
        "matched-at": "http://x.com/admin",
    }
    tm = FakeToolManager({
        "ffuf": {"json_file": {"results": [{"input": {"FUZZ": "backup.sql"}, "url": "http://x.com/backup.sql", "status": 200}]}},
        "sqlmap": {"stdout": "Parameter: id (GET)\nis vulnerable\n[*] shopdb\n"},
        "msfconsole": {"stdout_sequence": [
            "0  auxiliary/scanner/http/some_scanner  2021-01-01  normal  Yes  desc",
            "[+] target appears to be vulnerable.",
        ]},
    })
    db = FakeDB()
    phases = _phases(tm, db, target="http://x.com/item?id=1")
    phases.results["phase3_vulnerability_assessment"] = {
        "consolidated_findings": [{
            "title": nuclei_record["info"]["name"] + " (CVE-2021-9999)",
            "target": "http://x.com/admin",
            "severity": "high",
            "evidence": {"nuclei": nuclei_record},
        }]
    }

    result = phases.phase4_exploitation()

    assert result["mode"] == "active"
    tool_names = {c[0] for c in tm.calls}
    assert tool_names == {"ffuf", "sqlmap", "msfconsole"}
    titles = {v["title"] for v in db.vulnerabilities}
    assert any("SQL Injection" in t for t in titles)
    assert any("Metasploit check" in t for t in titles)
    assert any("backup.sql" in t for t in titles)


def test_phase4_stops_launching_new_active_tools_once_cancelled(monkeypatch):
    """Highest-blast-radius case for the /cancel fix: once a session is
    cancelled, no further sqlmap/msfconsole/ffuf invocation should start,
    even with exploitation fully enabled and the target allowlisted."""
    monkeypatch.setattr(config, "ENABLE_AUTO_EXPLOIT", True, raising=False)
    monkeypatch.setattr(config, "ENABLE_ADVANCED_EXPLOITATION", True, raising=False)
    monkeypatch.setenv("ALLOWED_TARGETS", "x.com")

    tm = FakeToolManager({
        "ffuf": {"json_file": {"results": []}},
        "sqlmap": {"stdout": "Parameter: id (GET)\nis vulnerable\n"},
        "msfconsole": {"stdout": "irrelevant"},
    })
    db = FakeDB()
    phases = _phases(tm, db, target="http://x.com/item?id=1")
    phases.results["phase3_vulnerability_assessment"] = {"consolidated_findings": []}

    cancellation_registry.request("s1")
    try:
        result = phases.phase4_exploitation()
    finally:
        cancellation_registry.clear("s1")

    assert result["mode"] == "active"
    assert tm.calls == []  # not even ffuf(dirs), the very first tool, should run


def test_sqlmap_only_runs_against_parameterized_urls_from_phase3(monkeypatch):
    monkeypatch.setattr(config, "ENABLE_AUTO_EXPLOIT", True, raising=False)
    monkeypatch.setattr(config, "ENABLE_ADVANCED_EXPLOITATION", True, raising=False)
    monkeypatch.setenv("ALLOWED_TARGETS", "x.com")

    tm = FakeToolManager({"ffuf": {"stdout": ""}})
    db = FakeDB()
    phases = _phases(tm, db, target="http://x.com")  # no query string on the bare target
    phases.results["phase3_vulnerability_assessment"] = {"consolidated_findings": []}

    phases.phase4_exploitation()

    assert not any(c[0] == "sqlmap" for c in tm.calls)
