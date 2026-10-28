# HackPilot core module
"""Sprint 3.3 + PDF/HTML parity: report annexes (subdomains, raw excerpts),
per-phase execution detail (tools/commands/ai_analysis), and the full
findings-by-phase breakdown used so the PDF download shows the same depth
as the HTML download."""

import logging

from jinja2 import DictLoader, Environment

from reporting.dynamic_reports import DynamicReportGenerator, _confirming_command_for


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
        {"title": "Subdomain discovered: api.x.com", "phase": "reconnaissance", "severity": "info", "evidence": {}},
        {"title": "Subdomain discovered: dev.x.com", "phase": "reconnaissance", "severity": "info", "evidence": {}},
        {
            "title": "SQL Injection confirmed",
            "phase": "exploitation",
            "severity": "critical",
            "target": "https://x.com/item?id=1",
            "cvss_score": 9.8,
            "remediation": "Use parameterized queries; validate and sanitize the 'id' parameter.",
            "evidence": {"sqlmap": {
                "raw_excerpt": "Parameter: id (GET)\nis vulnerable",
                "confirming_command": "sqlmap -u https://x.com/item?id=1 --batch --level=5 --risk=3 --dbs",
            }},
        },
    ],
    "phase_results": [
        {
            "phase_number": 1,
            "phase_name": "Phase 1: Intelligence Gathering & Reconnaissance",
            "status": "completed",
            "tools_used": ["nmap", "subfinder"],
            "commands_used": ["nmap -F -Pn x.com", "subfinder -d x.com -all -silent"],
            "ai_analysis": "2 subdomains found.",
            "execution_time": 12.5,
        },
        {
            "phase_number": 4,
            "phase_name": "Phase 4: Exploitation & Post-Exploitation",
            "status": "completed",
            "tools_used": ["sqlmap", "ffuf"],
            "commands_used": ["sqlmap -u https://x.com --batch --dbs"],
            "ai_analysis": "1 finding confirmed.",
            "execution_time": 30.0,
        },
    ],
}]


def test_build_annexes_collects_subdomains_and_excerpts():
    gen = _bare_generator()
    annexes = gen._build_annexes(SESSIONS)

    assert annexes["subdomains"] == ["api.x.com", "dev.x.com"]
    [excerpt] = annexes["raw_excerpts"]
    assert excerpt["source"] == "sqlmap"
    assert "is vulnerable" in excerpt["excerpt"]


def test_build_annexes_handles_sessions_with_no_evidence_or_phase_results():
    gen = _bare_generator()
    annexes = gen._build_annexes([{"target": "y.com", "vulnerabilities": []}])
    assert annexes == {"subdomains": [], "raw_excerpts": []}


def test_build_phase_detail_surfaces_exact_commands_per_phase():
    gen = _bare_generator()
    detail = gen._build_phase_detail(SESSIONS)

    assert [p["phase_number"] for p in detail] == [1, 4]
    phase1 = detail[0]
    assert phase1["tools_used"] == ["nmap", "subfinder"]
    assert phase1["commands_used"] == ["nmap -F -Pn x.com", "subfinder -d x.com -all -silent"]
    assert phase1["ai_analysis"] == "2 subdomains found."
    assert phase1["execution_time"] == 12.5


def test_group_findings_by_phase_sorts_by_severity_and_keeps_every_finding():
    gen = _bare_generator()
    vulns = [v for s in SESSIONS for v in s["vulnerabilities"]]
    grouped = gen._group_findings_by_phase(vulns)

    assert set(grouped.keys()) == {"reconnaissance", "exploitation"}
    assert len(grouped["reconnaissance"]) == 2
    assert grouped["exploitation"][0]["title"] == "SQL Injection confirmed"


def test_executive_summary_template_renders_phase_detail_and_full_findings():
    gen = _bare_generator()
    gen.jinja_env = Environment(loader=DictLoader({
        "executive_summary.html": open(
            "reporting/templates/executive_summary.html", encoding="utf-8"
        ).read()
    }))
    vulns = [v for s in SESSIONS for v in s["vulnerabilities"]]
    report_data = {
        "title": "Test Report",
        "generated_at": "2026-01-01",
        "target": "x.com",
        "metrics": {"total_vulnerabilities": 3, "critical_count": 1, "high_count": 0, "overall_risk_score": 5.0},
        "charts": {},
        "key_findings": [],
        "recommendations": [],
        "annexes": gen._build_annexes(SESSIONS),
        "phase_detail": gen._build_phase_detail(SESSIONS),
        "findings_by_phase": gen._group_findings_by_phase(vulns),
    }
    html = gen._export_html_report(report_data)

    assert "Annex A" in html and "Annex B" in html
    assert "api.x.com" in html
    assert "is vulnerable" in html
    assert "X-Report-SHA256" in html

    # The exact commands must appear verbatim - this is the gap between the
    # old PDF (tool-name-only) and the HTML artifact (full commands) that
    # this change closes.
    assert "nmap -F -Pn x.com" in html
    assert "sqlmap -u https://x.com --batch --dbs" in html
    assert "SQL Injection confirmed" in html
    assert "Subdomain discovered: api.x.com" in html


def test_confirming_command_for_reads_the_first_source_that_has_one():
    vuln = {"evidence": {
        "subfinder": {"subdomain": "api.x.com"},
        "amass": {"subdomain": "api.x.com", "confirming_command": "amass enum -d x.com -timeout 20 -silent"},
    }}
    assert _confirming_command_for(vuln) == "amass enum -d x.com -timeout 20 -silent"
    assert _confirming_command_for({"evidence": {}}) == ""
    assert _confirming_command_for({}) == ""


def test_build_remediation_priorities_excludes_info_and_sorts_by_severity():
    gen = _bare_generator()
    vulns = [v for s in SESSIONS for v in s["vulnerabilities"]]
    priorities = gen._build_remediation_priorities(vulns)

    # Both "Subdomain discovered" entries are info severity - not actionable.
    assert len(priorities) == 1
    item = priorities[0]
    assert item["title"] == "SQL Injection confirmed"
    assert item["severity"] == "critical"
    assert item["target"] == "https://x.com/item?id=1"
    assert item["cvss_score"] == 9.8
    assert item["confirming_command"] == "sqlmap -u https://x.com/item?id=1 --batch --level=5 --risk=3 --dbs"
    assert "parameterized queries" in item["remediation"]


def test_executive_summary_template_renders_remediation_and_confirming_command():
    gen = _bare_generator()
    gen.jinja_env = Environment(loader=DictLoader({
        "executive_summary.html": open(
            "reporting/templates/executive_summary.html", encoding="utf-8"
        ).read()
    }))
    vulns = [v for s in SESSIONS for v in s["vulnerabilities"]]
    report_data = {
        "title": "Test Report",
        "generated_at": "2026-01-01",
        "target": "x.com",
        "metrics": {"total_vulnerabilities": 3, "critical_count": 1, "high_count": 0, "overall_risk_score": 5.0},
        "charts": {},
        "key_findings": [],
        "recommendations": [],
        "annexes": gen._build_annexes(SESSIONS),
        "phase_detail": gen._build_phase_detail(SESSIONS),
        "findings_by_phase": gen._group_findings_by_phase(vulns),
        "remediation_priorities": gen._build_remediation_priorities(vulns),
    }
    html = gen._export_html_report(report_data)

    assert "Remediation Priorities" in html
    assert "sqlmap -u https://x.com/item?id=1 --batch --level=5 --risk=3 --dbs" in html
    assert "parameterized queries" in html


def test_markdown_export_contains_all_four_required_sections():
    gen = _bare_generator()
    vulns = [v for s in SESSIONS for v in s["vulnerabilities"]]
    report_data = {
        "title": "Test Report",
        "generated_at": "2026-01-01",
        "target": "x.com",
        "metrics": {"total_vulnerabilities": 3, "critical_count": 1, "high_count": 0,
                     "medium_count": 0, "low_count": 0, "overall_risk_score": 5.0},
        "phase_detail": gen._build_phase_detail(SESSIONS),
        "findings_by_phase": gen._group_findings_by_phase(vulns),
        "remediation_priorities": gen._build_remediation_priorities(vulns),
    }
    md = gen._export_markdown_report(report_data)

    assert "## Executive Summary" in md
    assert "## Findings Detail, by Phase" in md
    assert "## Tooling & Methodology" in md
    assert "## Remediation Priorities" in md
    assert "sqlmap -u https://x.com/item?id=1 --batch --level=5 --risk=3 --dbs" in md
    assert "nmap -F -Pn x.com" in md
