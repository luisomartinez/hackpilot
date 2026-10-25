# HackPilot core module
"""Sprint 3.3: report annexes (tools-per-phase, subdomains, raw excerpts)."""

import logging

from jinja2 import DictLoader, Environment

from reporting.dynamic_reports import DynamicReportGenerator


def _bare_generator():
    """Bypass __init__ (ChartGenerator/TrendAnalyzer/db pull in matplotlib/
    pandas we don't need here) - same pattern used for the Sprint 0 PDF
    smoke test."""
    gen = object.__new__(DynamicReportGenerator)
    gen.logger = logging.getLogger("test")
    return gen


SESSIONS = [{
    "target": "x.com",
    "vulnerabilities": [
        {"title": "Subdomain discovered: api.x.com", "evidence": {}},
        {"title": "Subdomain discovered: dev.x.com", "evidence": {}},
        {
            "title": "SQL Injection confirmed",
            "evidence": {"sqlmap": {"raw_excerpt": "Parameter: id (GET)\nis vulnerable"}},
        },
    ],
    "phase_results": [
        {"phase_name": "Phase 1: Intelligence Gathering & Reconnaissance", "tools_used": ["nmap", "subfinder"]},
        {"phase_name": "Phase 4: Exploitation & Post-Exploitation", "tools_used": ["sqlmap", "ffuf"]},
    ],
}]


def test_build_annexes_collects_subdomains_tools_and_excerpts():
    gen = _bare_generator()
    annexes = gen._build_annexes(SESSIONS)

    assert annexes["subdomains"] == ["api.x.com", "dev.x.com"]
    assert {p["phase_name"] for p in annexes["phase_tools"]} == {
        "Phase 1: Intelligence Gathering & Reconnaissance",
        "Phase 4: Exploitation & Post-Exploitation",
    }
    [excerpt] = annexes["raw_excerpts"]
    assert excerpt["source"] == "sqlmap"
    assert "is vulnerable" in excerpt["excerpt"]


def test_build_annexes_handles_sessions_with_no_evidence_or_phase_results():
    gen = _bare_generator()
    annexes = gen._build_annexes([{"target": "y.com", "vulnerabilities": []}])
    assert annexes == {"phase_tools": [], "subdomains": [], "raw_excerpts": []}


def test_executive_summary_template_renders_annex_sections():
    gen = _bare_generator()
    gen.jinja_env = Environment(loader=DictLoader({
        "executive_summary.html": open(
            "reporting/templates/executive_summary.html", encoding="utf-8"
        ).read()
    }))
    report_data = {
        "title": "Test Report",
        "generated_at": "2026-01-01",
        "target": "x.com",
        "metrics": {"total_vulnerabilities": 3, "critical_count": 1, "high_count": 0, "overall_risk_score": 5.0},
        "charts": {},
        "key_findings": [],
        "recommendations": [],
        "annexes": gen._build_annexes(SESSIONS),
    }
    html = gen._export_html_report(report_data)

    assert "Annex A" in html and "Annex B" in html and "Annex C" in html
    assert "api.x.com" in html
    assert "is vulnerable" in html
    assert "X-Report-SHA256" in html
