# HackPilot core module
"""Sprint 1: tool runners (exploitation/tools/*).

FakeToolManager stands in for EnterpriseToolManager - it never shells out,
just returns canned output per tool name, same contract real tool_manager
.run_command() has: {"success", "stdout", "stderr"}. testssl.sh/wapiti read
their results from a --jsonfile/-o path rather than stdout, so the fake
writes the canned JSON to whatever path the runner asked for.
"""

import json

from exploitation.tools.amass_runner import run_amass
from exploitation.tools.nuclei_runner import run_nuclei, update_nuclei_templates
from exploitation.tools.subfinder_runner import run_subfinder
from exploitation.tools.testssl_runner import run_testssl
from exploitation.tools.wapiti_runner import run_wapiti
from exploitation.tools.whatweb_runner import run_whatweb


class FakeToolManager:
    def __init__(self, canned):
        self.canned = canned  # {tool: {"success": bool, "stdout": str, "json_file": obj}}
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


def test_run_subfinder_parses_one_subdomain_per_line():
    tm = FakeToolManager({"subfinder": {"stdout": "api.x.com\nwww.x.com\n\n"}})
    findings = run_subfinder(tm, "x.com")
    assert {f["target"] for f in findings} == {"api.x.com", "www.x.com"}
    assert all(f["source"] == "subfinder" for f in findings)


def test_run_subfinder_returns_empty_on_failure():
    tm = FakeToolManager({"subfinder": {"success": False, "stderr": "not found"}})
    assert run_subfinder(tm, "x.com") == []


def test_run_subfinder_handles_missing_tool_manager_or_domain():
    assert run_subfinder(None, "x.com") == []
    assert run_subfinder(FakeToolManager({}), "") == []


def test_run_amass_parses_subdomains():
    tm = FakeToolManager({"amass": {"stdout": "dev.x.com\n"}})
    findings = run_amass(tm, "x.com")
    assert findings == [{
        "title": "Subdomain discovered: dev.x.com",
        "target": "dev.x.com",
        "source": "amass",
        "severity": "info",
        "evidence": {"subdomain": "dev.x.com"},
    }]


def test_run_whatweb_parses_default_plugin_output():
    tm = FakeToolManager({
        "whatweb": {"stdout": "http://x.com [200 OK] Apache[2.4.41], Title[Home], IP[1.2.3.4]\n"}
    })
    findings = run_whatweb(tm, ["x.com"])
    assert len(findings) == 1
    assert findings[0]["title"] == "Technology detected: Apache 2.4.41"
    assert findings[0]["target"] == "http://x.com"
    # IP/Title are request metadata, not a technology - must not become findings
    assert not any("IP" in f["title"] or "Title" in f["title"] for f in findings)


def test_run_nuclei_parses_jsonl_and_clamps_unknown_severity():
    line1 = json.dumps({
        "template-id": "CVE-2021-1234", "info": {"name": "Example Vuln", "severity": "high"},
        "matched-at": "https://x.com/admin",
    })
    line2 = json.dumps({
        "template-id": "weird-template", "info": {"name": "Weird", "severity": "banana"},
        "matched-at": "https://x.com/weird",
    })
    tm = FakeToolManager({"nuclei": {"stdout": f"{line1}\n{line2}\n"}})
    findings = run_nuclei(tm, ["https://x.com"])
    assert findings[0]["severity"] == "high"
    assert findings[1]["severity"] == "info"  # unrecognized severity clamped, not trusted blindly


def test_update_nuclei_templates_reports_success_flag():
    tm = FakeToolManager({"nuclei": {"success": True}})
    assert update_nuclei_templates(tm) is True


def test_run_testssl_reads_jsonfile_and_skips_ok_entries():
    tm = FakeToolManager({"testssl.sh": {"success": True, "json_file": [
        {"id": "TLS1", "severity": "OK", "finding": "fine", "port": "443"},
        {"id": "heartbleed", "severity": "CRITICAL", "finding": "vulnerable", "port": "443"},
    ]}})
    findings = run_testssl(tm, "x.com")
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["target"] == "x.com:443"


def test_run_wapiti_reads_jsonfile_and_categorizes_severity():
    tm = FakeToolManager({"wapiti": {"success": True, "json_file": {
        "vulnerabilities": {
            "SQL Injection": [{"info": "id param", "path": "/a?id=1"}],
            "Fingerprint web technologies": [{"info": "Apache", "path": "/"}],
        }
    }}})
    findings = run_wapiti(tm, "http://x.com")
    by_title = {f["title"]: f for f in findings}
    assert by_title["SQL Injection: id param"]["severity"] == "medium"
    assert by_title["Fingerprint web technologies: Apache"]["severity"] == "info"


def test_runners_never_raise_on_missing_inputs():
    tm = FakeToolManager({})
    assert run_testssl(tm, "") == []
    assert run_wapiti(tm, "") == []
    assert run_whatweb(tm, []) == []
    assert run_nuclei(tm, []) == []
