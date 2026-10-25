# HackPilot core module
"""Sprint 1: phase1_reconnaissance / phase3_vulnerability_assessment wiring
to the new tool runners + consolidation, on top of the unchanged nmap/nikto
behavior (regression coverage for principle #1: don't change existing
phase behavior when not explicitly asked to).
"""

import json

from advance_hackpilot import EnterprisePentestingPhases


class FakeToolManager:
    def __init__(self, canned):
        self.canned = canned
        self.calls = []

    def run_command(self, args, timeout=None):
        self.calls.append(list(args))
        spec = self.canned.get(args[0], {"success": True, "stdout": ""})
        if "json_file" in spec:
            for flag in ("--jsonfile", "-o"):
                if flag in args:
                    out_path = args[args.index(flag) + 1]
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(spec["json_file"], f)
        return {"success": spec.get("success", True), "stdout": spec.get("stdout", ""), "stderr": spec.get("stderr", "")}


class FakeDB:
    def __init__(self):
        self.vulnerabilities = []
        self.phase_results = {}

    def create_phase_result(self, session_id, phase_name, phase_number, results, ai_analysis=None, tools_used=None):
        rid = f"phase-{phase_number}"
        self.phase_results[rid] = {"tools_used": tools_used, "status": "running"}
        return rid

    def update_phase_result(self, result_id, status, completed_at=None, results=None, ai_analysis=None, execution_time=None):
        self.phase_results[result_id]["status"] = status

    def create_vulnerability(self, session_id, phase, severity, title, description,
                              cvss_score=None, cvss_vector=None, proof_of_concept=None,
                              remediation=None, references=None, sources=None,
                              validated=False, confidence=None, evidence=None):
        self.vulnerabilities.append({
            "phase": phase, "severity": severity, "title": title,
            "sources": sources, "validated": validated, "confidence": confidence,
        })
        return f"vuln-{len(self.vulnerabilities)}"


def _phases(tool_manager, db, target="https://x.com"):
    return EnterprisePentestingPhases(
        session_id="s1", ai_engine=None, tool_manager=tool_manager,
        target_info={"target": target}, db=db, cache=None, processor=None,
        exploitation=None, zero_day_detector=None, compliance=None, report_generator=None,
    )


def test_phase1_existing_nmap_behavior_is_unchanged():
    tm = FakeToolManager({"nmap": {"stdout": "80/tcp open http Apache\n"}})
    db = FakeDB()
    result = _phases(tm, db).phase1_reconnaissance()

    assert result["success"] is True
    assert result["open_ports"] == ["Port 80/tcp (httpApache)"]  # pre-existing nmap parsing, unchanged by Sprint 1
    nmap_calls = [c for c in tm.calls if c[0] == "nmap"]
    assert len(nmap_calls) == 1
    assert nmap_calls[0] == ["nmap", "-F", "-Pn", "--host-timeout", "30s", "x.com"]


def test_phase1_persists_consolidated_subdomain_and_tech_findings():
    tm = FakeToolManager({
        "nmap": {"stdout": "80/tcp open http Apache\n"},
        "subfinder": {"stdout": "api.x.com\n"},
        "amass": {"stdout": "api.x.com\n"},
        "whatweb": {"stdout": "http://api.x.com [200 OK] nginx[1.18.0]\n"},
    })
    db = FakeDB()
    result = _phases(tm, db).phase1_reconnaissance()

    assert result["subdomains"] == ["api.x.com"]
    titles = {v["title"]: v for v in db.vulnerabilities}
    assert titles["Subdomain discovered: api.x.com"]["sources"] == ["amass", "subfinder"]
    assert titles["Subdomain discovered: api.x.com"]["confidence"] == "info"  # passive-only
    assert "Technology detected: nginx 1.18.0" in titles


def test_phase1_recon_tool_failure_does_not_abort_the_phase():
    tm = FakeToolManager({"nmap": {"stdout": "80/tcp open http Apache\n"}, "subfinder": {"success": False}})
    db = FakeDB()
    result = _phases(tm, db).phase1_reconnaissance()
    assert result["success"] is True


def test_phase3_existing_nikto_behavior_is_unchanged_when_web_service_present():
    tm = FakeToolManager({"nikto": {"stdout": "+ some finding\n"}})
    db = FakeDB()
    phases = _phases(tm, db)
    phases.results["phase1_reconnaissance"] = {"open_ports": ["Port 80/tcp (http)"]}
    result = phases.phase3_vulnerability_assessment()

    assert result["success"] is True
    nikto_calls = [c for c in tm.calls if c[0] == "nikto"]
    assert nikto_calls == [["nikto", "-h", "https://x.com", "-maxtime", "30s", "-Tuning", "1,2,3"]]


def test_phase3_persists_consolidated_nuclei_testssl_wapiti_findings():
    nuclei_line = json.dumps({
        "template-id": "exposed-panel", "info": {"name": "Exposed Admin Panel", "severity": "high"},
        "matched-at": "https://x.com/admin",
    })
    tm = FakeToolManager({
        "nikto": {"stdout": ""},
        "nuclei": {"stdout": nuclei_line + "\n"},
        "testssl.sh": {"json_file": [{"id": "BEAST", "severity": "MEDIUM", "finding": "vulnerable", "port": "443"}]},
        "wapiti": {"json_file": {"vulnerabilities": {"SQL Injection": [{"info": "id param", "path": "/a"}]}}},
    })
    db = FakeDB()
    phases = _phases(tm, db)
    phases.results["phase1_reconnaissance"] = {"open_ports": ["Port 443/tcp (https)"], "subdomains": []}
    phases.phase3_vulnerability_assessment()

    titles = {v["title"] for v in db.vulnerabilities}
    assert any("Exposed Admin Panel" in t for t in titles)
    assert any("BEAST" in t for t in titles)
    assert any("SQL Injection" in t for t in titles)


def test_phase3_skips_new_tools_without_web_service_like_nikto_does():
    tm = FakeToolManager({})
    db = FakeDB()
    phases = _phases(tm, db)
    phases.results["phase1_reconnaissance"] = {"open_ports": []}
    phases.phase3_vulnerability_assessment()
    assert not any(c[0] in ("nuclei", "testssl.sh", "wapiti") for c in tm.calls)
