#!/usr/bin/env python3
# HackPilot core module
"""
Enterprise Reporting System for HackPilot
Dynamic report generation with analytics and trend analysis
"""

import os
import json
import logging
import base64
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import matplotlib

matplotlib.use("Agg")  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import pandas as pd
from jinja2 import Environment, FileSystemLoader, Template, TemplateNotFound

from database import get_db_manager


def _confirming_command_for(vuln: Dict[str, Any]) -> str:
    """The exact command that confirmed this finding, if the runner that
    found it recorded one (exploitation.tools.* runners attach
    'confirming_command' into each raw finding's evidence; consolidation
    keys evidence by source name, so this just needs the first match)."""
    for payload in (vuln.get("evidence") or {}).values():
        if isinstance(payload, dict) and payload.get("confirming_command"):
            return payload["confirming_command"]
    return ""


@dataclass
class ReportTemplate:
    name: str
    template_type: str
    description: str
    template_content: str
    required_data: List[str]


class ChartGenerator:
    """Generates charts and visualizations for reports"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Set up matplotlib style
        plt.style.use("seaborn-v0_8")
        sns.set_palette("husl")

    def create_vulnerability_severity_chart(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """Create vulnerability severity distribution chart"""
        try:
            # Count vulnerabilities by severity
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown").lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            if not severity_counts:
                return ""

            # Create pie chart
            fig, ax = plt.subplots(figsize=(10, 8))

            colors = {
                "critical": "#ff0000",
                "high": "#ff6600",
                "medium": "#ffcc00",
                "low": "#00cc00",
                "info": "#0066cc",
                "unknown": "#999999",
            }

            severities = list(severity_counts.keys())
            counts = list(severity_counts.values())
            chart_colors = [colors.get(sev, "#999999") for sev in severities]

            wedges, texts, autotexts = ax.pie(
                counts,
                labels=severities,
                autopct="%1.1f%%",
                colors=chart_colors,
                startangle=90,
            )

            ax.set_title(
                "Vulnerability Distribution by Severity", fontsize=16, fontweight="bold"
            )

            # Save to base64 string
            buffer = BytesIO()
            plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
            buffer.seek(0)

            chart_base64 = base64.b64encode(buffer.read()).decode()
            buffer.close()
            plt.close()

            return f"data:image/png;base64,{chart_base64}"

        except Exception as e:
            self.logger.error(f"Error creating vulnerability severity chart: {e}")
            return ""

    def create_timeline_chart(self, sessions: List[Dict[str, Any]]) -> str:
        """Create timeline chart of pentest sessions"""
        try:
            if not sessions:
                return ""

            # Prepare data
            dates = []
            session_names = []

            for session in sessions[-20:]:  # Last 20 sessions
                created_at = session.get("created_at", datetime.utcnow().isoformat())
                if isinstance(created_at, str):
                    date = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                else:
                    date = created_at

                dates.append(date)
                session_names.append(
                    f"{session.get('target', 'Unknown')} ({date.strftime('%m/%d')})"
                )

            # Create timeline plot
            fig, ax = plt.subplots(figsize=(14, 8))

            # Plot timeline
            ax.scatter(dates, range(len(dates)), alpha=0.7, s=100)

            # Add labels
            for i, (date, name) in enumerate(zip(dates, session_names)):
                ax.annotate(
                    name,
                    (date, i),
                    xytext=(10, 0),
                    textcoords="offset points",
                    va="center",
                    fontsize=9,
                )

            ax.set_xlabel("Date", fontsize=12)
            ax.set_ylabel("Sessions", fontsize=12)
            ax.set_title("Penetration Test Timeline", fontsize=16, fontweight="bold")

            # Format x-axis
            plt.xticks(rotation=45)
            ax.grid(True, alpha=0.3)

            # Save to base64 string
            buffer = BytesIO()
            plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
            buffer.seek(0)

            chart_base64 = base64.b64encode(buffer.read()).decode()
            buffer.close()
            plt.close()

            return f"data:image/png;base64,{chart_base64}"

        except Exception as e:
            self.logger.error(f"Error creating timeline chart: {e}")
            return ""

    def create_risk_heatmap(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Create risk assessment heatmap"""
        try:
            if not vulnerabilities:
                return ""

            # Prepare data for heatmap
            categories = {}
            for vuln in vulnerabilities:
                category = vuln.get("category", "Other")
                severity = vuln.get("severity", "unknown").lower()

                if category not in categories:
                    categories[category] = {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    }

                if severity in categories[category]:
                    categories[category][severity] += 1

            # Create DataFrame for heatmap
            df_data = []
            for category, severities in categories.items():
                df_data.append(
                    [
                        severities["critical"],
                        severities["high"],
                        severities["medium"],
                        severities["low"],
                    ]
                )

            df = pd.DataFrame(
                df_data,
                columns=["Critical", "High", "Medium", "Low"],
                index=list(categories.keys()),
            )

            # Create heatmap
            fig, ax = plt.subplots(figsize=(10, 8))

            sns.heatmap(df, annot=True, cmap="Reds", ax=ax, fmt="d")
            ax.set_title("Vulnerability Risk Heatmap", fontsize=16, fontweight="bold")
            ax.set_xlabel("Severity Level", fontsize=12)
            ax.set_ylabel("Vulnerability Category", fontsize=12)

            # Save to base64 string
            buffer = BytesIO()
            plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
            buffer.seek(0)

            chart_base64 = base64.b64encode(buffer.read()).decode()
            buffer.close()
            plt.close()

            return f"data:image/png;base64,{chart_base64}"

        except Exception as e:
            self.logger.error(f"Error creating risk heatmap: {e}")
            return ""


class TrendAnalyzer:
    """Analyzes trends across multiple pentest sessions"""

    def __init__(self):
        self.db = get_db_manager()
        self.logger = logging.getLogger(__name__)

    def analyze_trends(
        self, sessions: List[Dict[str, Any]], timeframe: str = "monthly"
    ) -> Dict[str, Any]:
        """Analyze trends across sessions"""
        trends = {
            "vulnerability_trends": self._analyze_vulnerability_trends(
                sessions, timeframe
            ),
            "target_trends": self._analyze_target_trends(sessions, timeframe),
            "severity_trends": self._analyze_severity_trends(sessions, timeframe),
            "tool_effectiveness": self._analyze_tool_effectiveness(sessions),
            "risk_evolution": self._analyze_risk_evolution(sessions, timeframe),
        }

        return trends

    def _analyze_vulnerability_trends(
        self, sessions: List[Dict[str, Any]], timeframe: str
    ) -> Dict[str, Any]:
        """Analyze vulnerability trends over time"""
        trends = {}

        # Group sessions by time period
        time_groups = self._group_sessions_by_time(sessions, timeframe)

        for period, period_sessions in time_groups.items():
            period_stats = {
                "total_vulnerabilities": 0,
                "avg_vulnerabilities_per_session": 0,
                "vulnerability_types": {},
                "session_count": len(period_sessions),
            }

            total_vulns = 0
            for session in period_sessions:
                session_vulns = session.get("vulnerabilities", [])
                total_vulns += len(session_vulns)

                # Count by type
                for vuln in session_vulns:
                    vuln_type = vuln.get("type", "unknown")
                    period_stats["vulnerability_types"][vuln_type] = (
                        period_stats["vulnerability_types"].get(vuln_type, 0) + 1
                    )

            period_stats["total_vulnerabilities"] = total_vulns
            period_stats["avg_vulnerabilities_per_session"] = (
                total_vulns / len(period_sessions) if period_sessions else 0
            )

            trends[period] = period_stats

        return trends

    def _analyze_severity_trends(
        self, sessions: List[Dict[str, Any]], timeframe: str
    ) -> Dict[str, Any]:
        """Analyze severity trends over time"""
        trends = {}

        time_groups = self._group_sessions_by_time(sessions, timeframe)

        for period, period_sessions in time_groups.items():
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }

            for session in period_sessions:
                session_vulns = session.get("vulnerabilities", [])
                for vuln in session_vulns:
                    severity = vuln.get("severity", "unknown").lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

            trends[period] = severity_counts

        return trends

    def _analyze_target_trends(
        self, sessions: List[Dict[str, Any]], timeframe: str
    ) -> Dict[str, Any]:
        """Analyze target trends"""
        trends = {}

        time_groups = self._group_sessions_by_time(sessions, timeframe)

        for period, period_sessions in time_groups.items():
            target_stats = {
                "unique_targets": set(),
                "target_types": {},
                "repeat_targets": [],
            }

            for session in period_sessions:
                target = session.get("target", "unknown")
                target_stats["unique_targets"].add(target)

                # Categorize target type (basic heuristic)
                if any(tld in target for tld in [".com", ".org", ".net"]):
                    target_type = "external"
                elif target.startswith("192.168.") or target.startswith("10."):
                    target_type = "internal"
                else:
                    target_type = "unknown"

                target_stats["target_types"][target_type] = (
                    target_stats["target_types"].get(target_type, 0) + 1
                )

            # Convert set to count
            target_stats["unique_targets"] = len(target_stats["unique_targets"])
            trends[period] = target_stats

        return trends

    def _analyze_tool_effectiveness(
        self, sessions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze tool effectiveness across sessions"""
        tool_stats = {}

        for session in sessions:
            phase_results = session.get("phase_results", [])

            for phase in phase_results:
                tools_used = phase.get("tools_used", [])
                vulnerabilities_found = len(
                    phase.get("results", {}).get("vulnerabilities", [])
                )

                for tool in tools_used:
                    if tool not in tool_stats:
                        tool_stats[tool] = {
                            "usage_count": 0,
                            "total_vulnerabilities": 0,
                            "avg_vulnerabilities": 0,
                        }

                    tool_stats[tool]["usage_count"] += 1
                    tool_stats[tool]["total_vulnerabilities"] += vulnerabilities_found

        # Calculate averages
        for tool, stats in tool_stats.items():
            if stats["usage_count"] > 0:
                stats["avg_vulnerabilities"] = (
                    stats["total_vulnerabilities"] / stats["usage_count"]
                )

        return tool_stats

    def _analyze_risk_evolution(
        self, sessions: List[Dict[str, Any]], timeframe: str
    ) -> Dict[str, Any]:
        """Analyze risk evolution over time"""
        risk_trends = {}

        time_groups = self._group_sessions_by_time(sessions, timeframe)

        for period, period_sessions in time_groups.items():
            risk_scores = []

            for session in period_sessions:
                # Calculate risk score for session
                session_vulns = session.get("vulnerabilities", [])
                session_risk = 0

                severity_weights = {
                    "critical": 10,
                    "high": 7,
                    "medium": 4,
                    "low": 2,
                    "info": 1,
                }

                for vuln in session_vulns:
                    severity = vuln.get("severity", "low").lower()
                    session_risk += severity_weights.get(severity, 1)

                risk_scores.append(session_risk)

            period_risk = {
                "avg_risk_score": (
                    sum(risk_scores) / len(risk_scores) if risk_scores else 0
                ),
                "max_risk_score": max(risk_scores) if risk_scores else 0,
                "min_risk_score": min(risk_scores) if risk_scores else 0,
                "session_count": len(period_sessions),
            }

            risk_trends[period] = period_risk

        return risk_trends

    def _group_sessions_by_time(
        self, sessions: List[Dict[str, Any]], timeframe: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group sessions by time period"""
        groups = {}

        for session in sessions:
            created_at = session.get("created_at", datetime.utcnow().isoformat())
            if isinstance(created_at, str):
                date = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            else:
                date = created_at

            if timeframe == "weekly":
                # Week starting Monday
                week_start = date - timedelta(days=date.weekday())
                key = week_start.strftime("%Y-W%U")
            elif timeframe == "monthly":
                key = date.strftime("%Y-%m")
            elif timeframe == "quarterly":
                quarter = (date.month - 1) // 3 + 1
                key = f"{date.year}-Q{quarter}"
            else:  # daily
                key = date.strftime("%Y-%m-%d")

            if key not in groups:
                groups[key] = []
            groups[key].append(session)

        return groups


class DynamicReportGenerator:
    """Dynamic report generator with multiple formats"""

    def __init__(self):
        self.db = get_db_manager()
        self.chart_generator = ChartGenerator()
        self.trend_analyzer = TrendAnalyzer()
        self.logger = logging.getLogger(__name__)

        # Initialize Jinja2 environment. executive_summary.html is a real,
        # version-controlled template under templates/ - it used to get
        # clobbered on every startup by a hardcoded fallback string here
        # (_create_default_templates), silently reverting any template
        # changes (e.g. the phase/command/findings detail sections) back to
        # a bare-bones version. That bootstrap write has been removed; the
        # committed template file is now the single source of truth.
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        os.makedirs(template_dir, exist_ok=True)
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))

    def generate_executive_report(
        self, sessions: List[Dict[str, Any]], timeframe: str = "monthly"
    ) -> Dict[str, Any]:
        """Generate executive-level report"""
        # Analyze trends across sessions
        trends = self.trend_analyzer.analyze_trends(sessions, timeframe)

        # Calculate executive metrics
        total_vulnerabilities = sum(len(s.get("vulnerabilities", [])) for s in sessions)

        all_vulnerabilities = []
        for session in sessions:
            all_vulnerabilities.extend(session.get("vulnerabilities", []))

        severity_counts = {}
        for vuln in all_vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Calculate overall risk score
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        total_risk = sum(
            severity_weights.get(sev, 1) * count
            for sev, count in severity_counts.items()
        )
        max_possible_risk = total_vulnerabilities * 10
        overall_risk_score = (
            min((total_risk / max_possible_risk * 10), 10)
            if max_possible_risk > 0
            else 0
        )

        # Generate insights
        insights = self._generate_executive_insights(trends, sessions)

        # Create visualizations
        charts = {}
        if all_vulnerabilities:
            charts["severity_distribution"] = (
                self.chart_generator.create_vulnerability_severity_chart(
                    all_vulnerabilities
                )
            )
            charts["risk_heatmap"] = self.chart_generator.create_risk_heatmap(
                all_vulnerabilities
            )

        if sessions:
            charts["timeline"] = self.chart_generator.create_timeline_chart(sessions)

        executive_report = {
            "title": "Executive Security Assessment Report",
            "generated_at": datetime.utcnow().strftime("%B %d, %Y"),
            "timeframe": timeframe,
            "session_count": len(sessions),
            "metrics": {
                "total_vulnerabilities": total_vulnerabilities,
                "critical_count": severity_counts.get("critical", 0),
                "high_count": severity_counts.get("high", 0),
                "medium_count": severity_counts.get("medium", 0),
                "low_count": severity_counts.get("low", 0),
                "overall_risk_score": round(overall_risk_score, 1),
                "unique_targets": len(
                    set(s.get("target", "unknown") for s in sessions)
                ),
            },
            "trends": trends,
            "insights": insights,
            "charts": charts,
            "key_findings": self._extract_key_findings(all_vulnerabilities),
            "recommendations": self._generate_strategic_recommendations(
                insights, trends
            ),
            "annexes": self._build_annexes(sessions),
            "phase_detail": self._build_phase_detail(sessions),
            "findings_by_phase": self._group_findings_by_phase(all_vulnerabilities),
            "remediation_priorities": self._build_remediation_priorities(all_vulnerabilities),
            "attack_chain_narrative": next(
                (s["attack_chain_narrative"] for s in sessions if s.get("attack_chain_narrative")),
                None,
            ),
        }

        return executive_report

    def _build_phase_detail(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Per-phase breakdown for the report: tools used, the exact commands
        run (from PhaseResult.commands_used, populated by
        EnterpriseToolManager.command_log), the engine's own analysis of the
        phase outcome, and timing - everything the HTML download ("same info
        as the artifact") needs to show per phase, not just an aggregate
        tool list."""
        detail = []
        for session in sessions:
            for phase in session.get("phase_results", []):
                detail.append({
                    "phase_number": phase.get("phase_number"),
                    "phase_name": phase.get("phase_name", "Unknown phase"),
                    "status": phase.get("status", "unknown"),
                    "tools_used": phase.get("tools_used") or [],
                    "commands_used": phase.get("commands_used") or [],
                    "ai_analysis": phase.get("ai_analysis") or "",
                    "execution_time": phase.get("execution_time"),
                })
        detail.sort(key=lambda p: (p["phase_number"] is None, p["phase_number"]))
        return detail

    def _group_findings_by_phase(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Every vulnerability row, grouped by phase - the PDF needs the same
        full findings (every subdomain, every open port, every tech
        detection) the HTML report shows, not just the top few 'key
        findings' used for the executive summary metrics."""
        by_phase: Dict[str, List[Dict[str, Any]]] = {}
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for vuln in vulnerabilities:
            phase = vuln.get("phase") or "unknown"
            by_phase.setdefault(phase, []).append({**vuln, "confirming_command": _confirming_command_for(vuln)})
        for findings in by_phase.values():
            findings.sort(key=lambda v: severity_rank.get(str(v.get("severity", "info")).lower(), 5))
        return by_phase

    def _build_remediation_priorities(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Every *actionable* finding (severity above 'info'), flattened
        across phases and sorted by severity - the "Remediation
        Priorities" section callers can hand straight to whoever owns
        fixing things, without them having to re-derive priority order
        from the full per-phase findings tables."""
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        actionable = [
            v for v in vulnerabilities
            if str(v.get("severity", "info")).lower() in severity_rank
        ]
        actionable.sort(key=lambda v: severity_rank.get(str(v.get("severity", "info")).lower(), 9))
        return [{
            "title": v.get("title"),
            "severity": v.get("severity"),
            "target": v.get("target"),
            "cvss_score": v.get("cvss_score"),
            "remediation": v.get("remediation") or "Review manually and confirm exploitability before prioritizing.",
            "confirming_command": _confirming_command_for(v),
        } for v in actionable]

    def _build_annexes(self, sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Annex data for the report template: discovered subdomains and raw
        tool-evidence excerpts. Per-phase tools/commands live in
        `_build_phase_detail` instead - that one has the exact argv (from
        PhaseResult.commands_used), not just the tool name list."""
        subdomains = set()
        raw_excerpts = []

        for session in sessions:
            for vuln in session.get("vulnerabilities", []):
                title = vuln.get("title", "")
                if title.startswith("Subdomain discovered:"):
                    subdomains.add(title.replace("Subdomain discovered:", "").strip())

                for source, payload in (vuln.get("evidence") or {}).items():
                    if not isinstance(payload, dict):
                        continue
                    excerpt = payload.get("raw_excerpt") or payload.get("raw")
                    if excerpt:
                        raw_excerpts.append({
                            "source": source,
                            "title": title,
                            "excerpt": str(excerpt)[:1500],
                        })

        return {
            "subdomains": sorted(subdomains),
            "raw_excerpts": raw_excerpts[:10],
        }

    def _generate_executive_insights(
        self, trends: Dict[str, Any], sessions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate executive-level insights"""
        insights = []

        # Vulnerability trend insight
        vuln_trends = trends.get("vulnerability_trends", {})
        if len(vuln_trends) >= 2:
            periods = sorted(vuln_trends.keys())
            latest = vuln_trends[periods[-1]]
            previous = vuln_trends[periods[-2]] if len(periods) > 1 else {}

            latest_avg = latest.get("avg_vulnerabilities_per_session", 0)
            previous_avg = previous.get("avg_vulnerabilities_per_session", 0)

            if previous_avg > 0:
                change_percent = ((latest_avg - previous_avg) / previous_avg) * 100
                trend_direction = (
                    "increased"
                    if change_percent > 5
                    else "decreased" if change_percent < -5 else "remained stable"
                )

                insights.append(
                    {
                        "type": "vulnerability_trend",
                        "title": "Vulnerability Trend Analysis",
                        "description": f"Average vulnerabilities per assessment {trend_direction} by {abs(change_percent):.1f}% compared to previous period.",
                        "impact": (
                            "high"
                            if abs(change_percent) > 20
                            else "medium" if abs(change_percent) > 5 else "low"
                        ),
                    }
                )

        # Risk evolution insight
        risk_trends = trends.get("risk_evolution", {})
        if len(risk_trends) >= 2:
            periods = sorted(risk_trends.keys())
            latest_risk = risk_trends[periods[-1]].get("avg_risk_score", 0)
            previous_risk = (
                risk_trends[periods[-2]].get("avg_risk_score", 0)
                if len(periods) > 1
                else 0
            )

            if previous_risk > 0:
                risk_change = ((latest_risk - previous_risk) / previous_risk) * 100

                insights.append(
                    {
                        "type": "risk_evolution",
                        "title": "Risk Evolution",
                        "description": f'Overall risk score has {"increased" if risk_change > 0 else "decreased"} by {abs(risk_change):.1f}%.',
                        "impact": "high" if abs(risk_change) > 25 else "medium",
                    }
                )

        # Tool effectiveness insight
        tool_effectiveness = trends.get("tool_effectiveness", {})
        if tool_effectiveness:
            most_effective = max(
                tool_effectiveness.items(),
                key=lambda x: x[1].get("avg_vulnerabilities", 0),
            )

            insights.append(
                {
                    "type": "tool_effectiveness",
                    "title": "Tool Performance",
                    "description": f'{most_effective[0]} is the most effective tool, finding an average of {most_effective[1]["avg_vulnerabilities"]:.1f} vulnerabilities per use.',
                    "impact": "medium",
                }
            )

        return insights

    def _extract_key_findings(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Extract key findings from vulnerabilities"""
        key_findings = []

        # Critical vulnerabilities
        critical_vulns = [
            v for v in vulnerabilities if v.get("severity", "").lower() == "critical"
        ]
        if critical_vulns:
            key_findings.append(
                {
                    "title": f"{len(critical_vulns)} Critical Vulnerabilities Identified",
                    "description": "Immediate action required to address critical security vulnerabilities that pose significant risk to the organization.",
                    "severity": "critical",
                }
            )

        # Common vulnerability types
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

        if vuln_types:
            most_common = max(vuln_types.items(), key=lambda x: x[1])
            key_findings.append(
                {
                    "title": f"{most_common[0]} Vulnerabilities Most Common",
                    "description": f"{most_common[1]} instances of {most_common[0]} vulnerabilities found across assessments.",
                    "severity": "high",
                }
            )

        return key_findings

    def _generate_strategic_recommendations(
        self, insights: List[Dict[str, Any]], trends: Dict[str, Any]
    ) -> List[str]:
        """Generate strategic recommendations for executives"""
        recommendations = []

        # Based on insights
        for insight in insights:
            if insight["type"] == "vulnerability_trend" and insight["impact"] == "high":
                if "increased" in insight["description"]:
                    recommendations.append(
                        "Increase security assessment frequency and implement more proactive security controls"
                    )
                else:
                    recommendations.append(
                        "Continue current security practices while monitoring for emerging threats"
                    )

            elif insight["type"] == "risk_evolution" and insight["impact"] == "high":
                recommendations.append(
                    "Implement immediate risk mitigation strategies and increase security budget allocation"
                )

        # General strategic recommendations
        recommendations.extend(
            [
                "Establish regular executive security briefings to maintain visibility into security posture",
                "Consider implementing automated continuous security monitoring",
                "Invest in security awareness training for all employees",
                "Evaluate cyber insurance coverage based on current risk profile",
            ]
        )

        return recommendations[:6]  # Limit to top 6 recommendations

    def generate_technical_report(self, session_data: Dict[str, Any]) -> str:
        """Generate detailed technical report"""
        # jinja2's get_template() raises TemplateNotFound rather than returning
        # None when the file is missing - no "technical_report.html" is ever
        # created by _create_default_templates (only executive_summary.html is),
        # so this always needs the text fallback below.
        try:
            template = self.jinja_env.get_template("technical_report.html")
        except TemplateNotFound:
            return self._generate_text_technical_report(session_data)

        return template.render(session_data=session_data)

    def _generate_text_technical_report(self, session_data: Dict[str, Any]) -> str:
        """Generate basic text technical report"""
        report_lines = [
            f"TECHNICAL PENETRATION TEST REPORT",
            f"=" * 50,
            f"Target: {session_data.get('target', 'Unknown')}",
            f"Date: {session_data.get('created_at', 'Unknown')}",
            f"Scope: {session_data.get('scope', 'Unknown')}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 20,
        ]

        vulnerabilities = session_data.get("vulnerabilities", [])
        if vulnerabilities:
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            report_lines.append(f"Total Vulnerabilities Found: {len(vulnerabilities)}")
            for severity, count in severity_counts.items():
                report_lines.append(f"  - {severity.title()}: {count}")

        report_lines.extend(
            [
                "",
                "DETAILED FINDINGS",
                "-" * 20,
            ]
        )

        for i, vuln in enumerate(vulnerabilities[:10], 1):  # Top 10 vulnerabilities
            report_lines.extend(
                [
                    f"{i}. {vuln.get('title', 'Unknown Vulnerability')}",
                    f"   Severity: {vuln.get('severity', 'Unknown')}",
                    f"   Description: {vuln.get('description', 'No description available')[:200]}",
                    f"   Recommendation: {vuln.get('remediation', 'No recommendation available')[:200]}",
                    "",
                ]
            )

        return "\n".join(report_lines)

    def export_report(
        self, report_data: Dict[str, Any], format_type: str = "html"
    ) -> str:
        """Export report in specified format"""
        if format_type.lower() == "html":
            return self._export_html_report(report_data)
        elif format_type.lower() == "pdf":
            return self._export_pdf_report(report_data)
        elif format_type.lower() == "json":
            return json.dumps(report_data, indent=2, default=str)
        elif format_type.lower() in ("markdown", "md"):
            return self._export_markdown_report(report_data)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def _export_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """Export report as Markdown: the same four sections as the HTML/PDF
        report (executive summary, findings detail, tooling & methodology,
        remediation priorities), as plain text for pasting into a ticket,
        chat, or wiki page rather than opening a PDF viewer."""
        metrics = report_data.get("metrics", {})
        lines = [
            f"# {report_data.get('title', 'Security Assessment Report')}",
            "",
            f"**Generated:** {report_data.get('generated_at', '')}  ",
            f"**Target:** {report_data.get('target', '')}",
            "",
            "## Executive Summary",
            "",
            f"- Total findings: {metrics.get('total_vulnerabilities', 0)}",
            f"- Critical: {metrics.get('critical_count', 0)} | High: {metrics.get('high_count', 0)} "
            f"| Medium: {metrics.get('medium_count', 0)} | Low: {metrics.get('low_count', 0)}",
            f"- Overall risk score: {metrics.get('overall_risk_score', 0)}/10",
            "",
        ]

        remediation = report_data.get("remediation_priorities") or []
        lines.append("## Remediation Priorities")
        lines.append("")
        if remediation:
            lines.append("| Severity | Finding | Target | CVSS | Confirming command |")
            lines.append("|---|---|---|---|---|")
            for item in remediation:
                cmd = f"`{item['confirming_command']}`" if item.get("confirming_command") else "-"
                lines.append(
                    f"| {item.get('severity', '')} | {item.get('title', '')} | "
                    f"{item.get('target', '')} | {item.get('cvss_score', '-')} | {cmd} |"
                )
        else:
            lines.append("No actionable (above-info) findings in this session.")
        lines.append("")

        lines.append("## Findings Detail, by Phase")
        lines.append("")
        for phase, findings in (report_data.get("findings_by_phase") or {}).items():
            lines.append(f"### {phase.capitalize()} ({len(findings)} finding(s))")
            lines.append("")
            for f in findings:
                cvss_suffix = f", CVSS {f['cvss_score']}" if f.get("cvss_score") else ""
                lines.append(f"**{f.get('title', '')}** - severity: {f.get('severity', '')}{cvss_suffix}")
                if f.get("target"):
                    lines.append(f"- Target/parameter: `{f['target']}`")
                if f.get("confirming_command"):
                    lines.append(f"- Confirming command: `{f['confirming_command']}`")
                if f.get("sources"):
                    lines.append(f"- Sources: {', '.join(f['sources'])}")
                lines.append("")

        lines.append("## Tooling & Methodology")
        lines.append("")
        for phase in report_data.get("phase_detail") or []:
            lines.append(f"### {phase.get('phase_name', '')} ({phase.get('status', '')})")
            lines.append("")
            if phase.get("tools_used"):
                lines.append(f"Tools: {', '.join(phase['tools_used'])}")
                lines.append("")
            for cmd in phase.get("commands_used") or []:
                lines.append(f"```\n{cmd}\n```")
            if phase.get("ai_analysis"):
                lines.append(f"\n{phase['ai_analysis']}")
            lines.append("")

        return "\n".join(lines)

    def _export_html_report(self, report_data: Dict[str, Any]) -> str:
        """Export report as HTML"""
        try:
            template = self.jinja_env.get_template("executive_summary.html")
            return template.render(
                report_data=report_data,
                metrics=report_data.get("metrics", {}),
                severity_chart=report_data.get("charts", {}).get(
                    "severity_distribution", ""
                ),
                key_findings=report_data.get("key_findings", []),
                recommendations=report_data.get("recommendations", []),
                annexes=report_data.get("annexes", {}),
                phase_detail=report_data.get("phase_detail", []),
                findings_by_phase=report_data.get("findings_by_phase", {}),
                remediation_priorities=report_data.get("remediation_priorities", []),
                attack_chain_narrative=report_data.get("attack_chain_narrative"),
            )
        except Exception as e:
            self.logger.error(f"Error exporting HTML report: {e}")
            return (
                f"<html><body><h1>Error generating report: {str(e)}</h1></body></html>"
            )

    def _export_pdf_report(self, report_data: Dict[str, Any]) -> str:
        """Export report as PDF (returns file path). Renders the same HTML
        report through WeasyPrint rather than just saving the HTML - this
        previously always silently returned an .html file with a '.pdf'-
        sounding docstring and no actual PDF was ever produced.

        The rendered bytes are handed to security.report_crypto, which
        encrypts them at rest (returning a '.pdf.enc' path) when
        REPORT_ENCRYPTION_KEY is configured, or writes plain '.pdf'
        otherwise - callers read it back with read_report_file()."""
        html_content = self._export_html_report(report_data)
        pdf_path = f"/tmp/report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"

        try:
            from weasyprint import HTML
            pdf_bytes = HTML(string=html_content).write_pdf()
            from security.report_crypto import write_report_file
            return write_report_file(pdf_path, pdf_bytes)
        except ImportError:
            self.logger.warning("weasyprint not installed; falling back to HTML export")
        except Exception as e:
            self.logger.error(f"Error exporting PDF report: {e}")

        # Degraded-mode fallback only (weasyprint missing/broken) - left
        # unencrypted so the download route's existing `.endswith(".html")`
        # branch keeps working without also having to understand ".html.enc".
        html_path = pdf_path.replace(".pdf", ".html")
        with open(html_path, "w") as f:
            f.write(html_content)
        return html_path
