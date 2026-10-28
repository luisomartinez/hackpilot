# HackPilot core module
"""Plugin framework: registry gating (disabled by default - backward
compatible), and each plugin's own command construction / output parsing.
"""

import json

import pytest

from plugins import run_phase_plugins
from plugins.base import Plugin, PluginContext, PluginResult
from plugins.sqlmap_api_plugin import _assert_safe_options, SqlmapApiPlugin
from datetime import datetime


class FakeToolManager:
    def __init__(self, canned):
        self.canned = canned
        self.calls = []

    def run_command(self, args, timeout=None):
        self.calls.append(list(args))
        spec = self.canned.get(args[0], {"success": True, "stdout": ""})
        if "json_file" in spec:
            for flag in ("-o", "-f"):
                if flag in args:
                    out_path = args[args.index(flag) + 1]
                    suffix = ".json" if flag == "-o" else ".json"
                    path = out_path if out_path.endswith(".json") else out_path + suffix
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(spec["json_file"], f)
        if "xml_file" in spec and "-oX" in args:
            out_path = args[args.index("-oX") + 1]
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(spec["xml_file"])
        return {"success": spec.get("success", True), "stdout": spec.get("stdout", ""), "stderr": spec.get("stderr", "")}


def test_run_phase_plugins_is_disabled_by_default(monkeypatch):
    """Backward-compat constraint: with no ENABLE_*_PLUGIN set, nothing
    from the registry runs - findings list is empty, tool_manager is
    never touched."""
    for key in list(__import__("os").environ):
        if key.startswith("ENABLE_") and key.endswith("_PLUGIN"):
            monkeypatch.delenv(key, raising=False)
    tm = FakeToolManager({})
    ctx = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com")
    findings = run_phase_plugins("reconnaissance", ctx)
    assert findings == []
    assert tm.calls == []


def test_run_phase_plugins_runs_an_enabled_applicable_plugin(monkeypatch):
    monkeypatch.setenv("ENABLE_CRTSH_PLUGIN", "true")
    monkeypatch.setenv("ENABLE_THEHARVESTER_PLUGIN", "false")

    import plugins.crtsh_plugin as crtsh_module

    class _FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return [{"name_value": "api.x.com\n*.x.com"}]

    class _FakeRequests:
        @staticmethod
        def get(url, timeout=None):
            return _FakeResp()

    monkeypatch.setattr("builtins.__import__", __import__)  # sanity no-op
    import sys
    sys.modules["requests"] = _FakeRequests()

    tm = FakeToolManager({})
    ctx = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com")
    findings = run_phase_plugins("reconnaissance", ctx)

    titles = {f["title"] for f in findings}
    assert "Subdomain discovered: api.x.com" in titles
    assert "Subdomain discovered: x.com" in titles  # "*.x.com" stripped of wildcard


def test_run_phase_plugins_skips_a_non_applicable_plugin(monkeypatch):
    monkeypatch.setenv("ENABLE_CRTSH_PLUGIN", "true")
    tm = FakeToolManager({})
    # Bare IP target - crt.sh's is_applicable() must refuse (no domain to query).
    ctx = PluginContext(tool_manager=tm, target="203.0.113.10", scan_host="203.0.113.10")
    findings = run_phase_plugins("reconnaissance", ctx)
    assert findings == []


def test_run_phase_plugins_isolates_a_plugin_that_raises(monkeypatch):
    monkeypatch.setenv("ENABLE_THEHARVESTER_PLUGIN", "true")
    tm = FakeToolManager({"theHarvester": {"success": False, "stderr": "boom"}})
    ctx = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com")
    # Must not raise even though the underlying tool call "failed".
    findings = run_phase_plugins("reconnaissance", ctx)
    assert findings == []


def test_nmap_vulners_plugin_parses_cve_table_from_xml():
    from plugins.nmap_vulners_plugin import NmapVulnersPlugin

    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host><ports><port portid="443">
        <script id="vulners">
          <table>
            <elem key="id">CVE-2021-1234</elem>
            <elem key="cvss">9.8</elem>
          </table>
        </script>
      </port></ports></host>
    </nmaprun>"""
    tm = FakeToolManager({"nmap": {"xml_file": xml}})
    ctx = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com")
    result = NmapVulnersPlugin().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0]["evidence"]["cve_id"] == "CVE-2021-1234"
    assert result.findings[0]["severity"] == "critical"


def test_nmap_vulners_plugin_requires_an_api_key(monkeypatch):
    """Confirmed live: without VULNERS_API_KEY, the script only emits an
    informational "Ran without an API key" notice - no CVE table at all -
    so running it is a guaranteed-empty waste of scan time."""
    from plugins.nmap_vulners_plugin import NmapVulnersPlugin
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)
    assert NmapVulnersPlugin().is_applicable(PluginContext(tool_manager=None, target="x", scan_host="x")) is False
    monkeypatch.setenv("VULNERS_API_KEY", "fake-key")
    assert NmapVulnersPlugin().is_applicable(PluginContext(tool_manager=None, target="x", scan_host="x")) is True


def test_nikto_json_plugin_is_applicable_only_with_a_web_service():
    from plugins.nikto_json_plugin import NiktoJsonPlugin
    tm = FakeToolManager({})
    ctx_no_web = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com", has_web_service=False)
    ctx_web = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com", has_web_service=True)
    assert NiktoJsonPlugin().is_applicable(ctx_no_web) is False
    assert NiktoJsonPlugin().is_applicable(ctx_web) is True


def test_nikto_json_plugin_parses_vulnerabilities():
    """-Format json's real top-level shape (confirmed live) is a LIST of
    per-host records, each with its own "vulnerabilities" list - not one
    flat dict."""
    from plugins.nikto_json_plugin import NiktoJsonPlugin
    tm = FakeToolManager({"nikto": {"json_file": [{"host": "x.com", "vulnerabilities": [
        {"id": "999100", "msg": "X-Frame-Options missing", "url": "/"},
    ]}]}})
    ctx = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com", has_web_service=True)
    result = NiktoJsonPlugin().run(ctx)
    assert any("X-Frame-Options missing" in f["title"] for f in result.findings)


def test_nikto_json_plugin_excludes_its_own_connection_failure_notice():
    """Confirmed live: nikto's "[FAIL] Unable to connect" notice shows up
    *inside* the vulnerabilities list with id "FAIL" - same failure mode
    already fixed for the plain-text nikto parser this session."""
    from plugins.nikto_json_plugin import NiktoJsonPlugin
    tm = FakeToolManager({"nikto": {"json_file": [{"host": "x.com", "vulnerabilities": [
        {"id": "FAIL", "msg": "Unable to connect to x.com:443.", "url": "/"},
    ]}]}})
    ctx = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com", has_web_service=True)
    result = NiktoJsonPlugin().run(ctx)
    assert result.findings == []


def test_wpscan_plugin_is_applicable_from_tech_fingerprint():
    from plugins.wpscan_plugin import WPScanPlugin
    tm = FakeToolManager({})
    ctx = PluginContext(
        tool_manager=tm, target="https://x.com", scan_host="x.com", has_web_service=True,
        tech_findings=[{"title": "Technology detected: WordPress 6.4"}],
    )
    assert WPScanPlugin().is_applicable(ctx) is True


def test_wpscan_plugin_parses_version_and_plugin_vulnerabilities():
    from plugins.wpscan_plugin import WPScanPlugin
    data = {
        "version": {"vulnerabilities": [{"title": "WordPress <6.5 - XSS"}]},
        "plugins": {"akismet": {"vulnerabilities": [{"title": "Akismet - SQLi"}]}},
        "users": {"admin": {}},
    }
    tm = FakeToolManager({"wpscan": {"json_file": data}})
    ctx = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com", has_web_service=True)
    result = WPScanPlugin().run(ctx)
    titles = {f["title"] for f in result.findings}
    assert any("WordPress <6.5 - XSS" in t for t in titles)
    assert any("Akismet - SQLi" in t for t in titles)
    assert any("admin" in t for t in titles)


def test_joomscan_plugin_is_applicable_from_tech_fingerprint():
    from plugins.joomscan_plugin import JoomScanPlugin
    tm = FakeToolManager({})
    ctx_no = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com", has_web_service=True, tech_findings=[])
    ctx_yes = PluginContext(
        tool_manager=tm, target="https://x.com", scan_host="x.com", has_web_service=True,
        tech_findings=[{"title": "Technology detected: Joomla 4.2"}],
    )
    assert JoomScanPlugin().is_applicable(ctx_no) is False
    assert JoomScanPlugin().is_applicable(ctx_yes) is True


def test_joomscan_plugin_extracts_cve_from_stdout():
    from plugins.joomscan_plugin import JoomScanPlugin
    tm = FakeToolManager({"joomscan": {"stdout": "[++] Vulnerability found: CVE-2023-9999 in com_users\n"}})
    ctx = PluginContext(tool_manager=tm, target="https://x.com", scan_host="x.com", has_web_service=True)
    result = JoomScanPlugin().run(ctx)
    assert any("CVE-2023-9999" in f["title"] for f in result.findings)


def test_sqlmap_api_plugin_is_applicable_only_with_a_query_parameter():
    ctx_param = PluginContext(tool_manager=None, target="https://x.com/item?id=1", scan_host="x.com")
    ctx_no_param = PluginContext(tool_manager=None, target="https://x.com/", scan_host="x.com")
    assert SqlmapApiPlugin().is_applicable(ctx_param) is True
    assert SqlmapApiPlugin().is_applicable(ctx_no_param) is False


def test_sqlmap_api_plugin_rejects_forbidden_options():
    with pytest.raises(AssertionError):
        _assert_safe_options({"osShell": True})
    with pytest.raises(AssertionError):
        _assert_safe_options({"dumpAll": True})
    _assert_safe_options({"level": 5, "risk": 3, "getDbs": True})  # must not raise


def test_sqlmap_api_plugin_parses_scan_data():
    data = [
        {"type": 1, "value": "boolean-based blind"},
        {"type": 2, "value": "MySQL >= 5.0"},
        {"type": 9, "value": ["shopdb", "information_schema"]},
    ]
    findings = SqlmapApiPlugin._parse_data(data, "https://x.com/item?id=1", "sqlmapapi.py -s -p 8775")
    assert len(findings) == 1
    evidence = findings[0]["evidence"]
    assert evidence["dbms_fingerprint"] == "MySQL >= 5.0"
    assert evidence["databases_enumerated"] == ["shopdb", "information_schema"]
    assert evidence["extraction_not_executed"] is True
