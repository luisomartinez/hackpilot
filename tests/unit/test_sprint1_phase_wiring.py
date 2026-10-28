# HackPilot core module
"""Sprint 1: phase1_reconnaissance / phase3_vulnerability_assessment wiring
to the new tool runners + consolidation, on top of the unchanged nmap/nikto
behavior (regression coverage for principle #1: don't change existing
phase behavior when not explicitly asked to).
"""

import json

from advance_hackpilot import EnterprisePentestingPhases, cancellation_registry


class FakeToolManager:
    def __init__(self, canned):
        self.canned = canned
        self.calls = []
        self.command_log = []

    def run_command(self, args, timeout=None):
        self.calls.append(list(args))
        spec = self.canned.get(args[0], {"success": True, "stdout": ""})
        if "json_file" in spec:
            for flag in ("--jsonfile", "-o"):
                if flag in args:
                    out_path = args[args.index(flag) + 1]
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(spec["json_file"], f)
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
        if commands_used is not None:
            self.phase_results[result_id]["commands_used"] = commands_used

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


def test_phase1_stops_launching_new_tools_once_session_is_cancelled():
    """Real bug, confirmed live: cancelling a session used to only flip the
    DB status while the phase kept launching its remaining tools (amass
    killed mid-run -> whatweb started next anyway). Once cancelled, no
    tool past the one already in flight when cancel was requested should
    start."""
    tm = FakeToolManager({
        "nmap": {"stdout": "80/tcp open http Apache\n"},
        "subfinder": {"stdout": "api.x.com\n"},
        "amass": {"stdout": "api.x.com\n"},
        "whatweb": {"stdout": "http://api.x.com [200 OK] nginx[1.18.0]\n"},
    })
    db = FakeDB()
    cancellation_registry.request("s1")
    try:
        result = _phases(tm, db).phase1_reconnaissance()
    finally:
        cancellation_registry.clear("s1")

    called_tools = {c[0] for c in tm.calls}
    # nmap has no pre-check (cancellation is only ever requested after a
    # phase has started, never before), but subfinder/amass/whatweb must
    # not run once cancelled.
    assert called_tools == {"nmap"}
    assert result["subdomains"] == []


def test_phase1_skips_dns_subdomain_enumeration_for_an_ip_target():
    """subfinder/amass enumerate subdomains of a *domain* - there is none
    for a bare IP target, so running them would only burn their timeouts
    (up to 900s for amass) for a guaranteed-empty result. nmap and whatweb
    still run - a web service on an IP is just as real as one on a domain."""
    tm = FakeToolManager({
        "nmap": {"stdout": "80/tcp open http Apache\n"},
        "whatweb": {"stdout": "http://203.0.113.10 [200 OK] nginx[1.18.0]\n"},
    })
    db = FakeDB()
    result = _phases(tm, db, target="203.0.113.10").phase1_reconnaissance()

    called_tools = {c[0] for c in tm.calls}
    assert called_tools == {"nmap", "whatweb"}
    assert result["subdomains"] == []
    titles = {v["title"]: v for v in db.vulnerabilities}
    assert "Technology detected: nginx 1.18.0" in titles
    assert db.phase_results["phase-1"]["tools_used"] == ["nmap", "whatweb"]


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
        "testssl": {"json_file": [{"id": "BEAST", "severity": "MEDIUM", "finding": "vulnerable", "port": "443"}]},
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
    assert not any(c[0] in ("nuclei", "testssl", "wapiti") for c in tm.calls)


def test_phase3_runs_all_tools_against_a_bare_ip_target_same_as_a_domain():
    """has_web_service is detected from open-port strings, not hostname
    format - a web service on a bare IP must trigger the same nikto/
    nuclei/testssl/wapiti run a domain target would."""
    nuclei_line = json.dumps({
        "template-id": "exposed-panel", "info": {"name": "Exposed Admin Panel", "severity": "high"},
        "matched-at": "https://203.0.113.10/admin",
    })
    tm = FakeToolManager({
        "nikto": {"stdout": "+ some finding\n"},
        "nuclei": {"stdout": nuclei_line + "\n"},
        "testssl": {"json_file": []},
        "wapiti": {"json_file": {}},
    })
    db = FakeDB()
    phases = _phases(tm, db, target="203.0.113.10")
    phases.results["phase1_reconnaissance"] = {"open_ports": ["Port 443/tcp (https)"], "subdomains": []}
    result = phases.phase3_vulnerability_assessment()

    assert result["success"] is True
    called_tools = {c[0] for c in tm.calls}
    assert {"nikto", "nuclei", "testssl", "wapiti"} <= called_tools
    titles = {v["title"] for v in db.vulnerabilities}
    assert any("Exposed Admin Panel" in t for t in titles)
