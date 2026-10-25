#!/usr/bin/env python3
# HackPilot core module
"""Per-finding evidence persistence for the report's annexes (Sprint 3.2).

Writes evidence/<session_id>/<finding_id>/ containing:
  - evidence.json: the raw per-source payloads findings_consolidator
    already captured (sources -> raw tool output), unchanged.
  - request.http / response.http: only written when a source's raw
    payload actually contains a real HTTP transcript - wapiti's
    "http_request" field, or nuclei's "request"/"response" fields when
    run with -irr. Never fabricates a transcript a tool didn't give us.
  - reproduction_steps.txt: a short numbered summary built from whatever
    is available (target, contributing tools, confidence) - honest
    reproduction guidance, not a replay script.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger("hackpilot.reporting.evidence_store")


def _extract_http_transcript(source_evidence: Any) -> Dict[str, str]:
    """Pull out whatever real request/response text a tool's raw payload
    happens to contain. Returns {} when there is none."""
    if not isinstance(source_evidence, dict):
        return {}

    transcript = {}
    if source_evidence.get("http_request"):  # wapiti
        transcript["request"] = str(source_evidence["http_request"])
    if source_evidence.get("request"):  # nuclei with -irr
        transcript["request"] = str(source_evidence["request"])
    if source_evidence.get("response"):  # nuclei with -irr
        transcript["response"] = str(source_evidence["response"])
    return transcript


def save_evidence(session_id: str, finding_id: str, finding: Dict[str, Any], base_dir: str = "evidence") -> str:
    """Persist `finding`'s evidence under base_dir/<session_id>/<finding_id>/.
    Returns the directory path. Never raises - a write failure is logged
    and the pipeline continues without evidence for that finding, same
    graceful-degradation stance as the rest of the reporting pipeline."""
    try:
        out_dir = Path(base_dir) / session_id / finding_id
        out_dir.mkdir(parents=True, exist_ok=True)

        evidence = finding.get("evidence") or {}
        (out_dir / "evidence.json").write_text(json.dumps(evidence, indent=2, default=str), encoding="utf-8")

        for source, source_evidence in evidence.items():
            transcript = _extract_http_transcript(source_evidence)
            if "request" in transcript:
                (out_dir / "request.http").write_text(transcript["request"], encoding="utf-8")
            if "response" in transcript:
                (out_dir / "response.http").write_text(transcript["response"], encoding="utf-8")

        sources = finding.get("sources") or []
        steps = [
            f"1. Target: {finding.get('target', 'unknown')}",
            f"2. Finding: {finding.get('title', 'unknown')}",
            f"3. Reported by: {', '.join(sources) if sources else 'unknown tool'} "
            f"(confidence: {finding.get('confidence', 'unknown')}).",
            "4. Re-run the same tool(s) against the target to confirm; see evidence.json "
            "for the raw per-source output this finding was built from.",
        ]
        (out_dir / "reproduction_steps.txt").write_text("\n".join(steps), encoding="utf-8")

        return str(out_dir)
    except OSError as e:
        logger.warning("Could not save evidence for finding %s: %s", finding_id, e)
        return ""
