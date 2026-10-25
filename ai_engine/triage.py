#!/usr/bin/env python3
# HackPilot core module
"""Local-only false-positive triage for consolidated findings (Sprint 3.5).

Gated by USE_AI (.env, default "false"). When enabled, reuses the
existing OllamaProvider (ai_engine/providers.py) against a locally-running
Ollama instance - LOCAL_LLM_ENDPOINT/LOCAL_LLM_MODEL, the same env vars
the rest of the project already uses for local models. Never calls any
remote/third-party AI API: if Ollama isn't reachable, triage is skipped
entirely rather than falling back to a cloud provider.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hackpilot.ai_engine.triage")


def _ai_enabled() -> bool:
    return os.getenv("USE_AI", "false").strip().lower() == "true"


def _build_prompt(finding: Dict[str, Any]) -> str:
    return (
        "You are a security analyst triaging an automated scan finding. "
        "Classify its probability of being a false positive. "
        "Respond with ONLY a JSON object: "
        '{"fp_probability": <float 0.0-1.0>, "reason": "<one sentence>"}.\n\n'
        f"Title: {finding.get('title', '')}\n"
        f"Severity: {finding.get('severity', '')}\n"
        f"Target: {finding.get('target', finding.get('proof_of_concept', ''))}\n"
        f"Reported by: {', '.join(finding.get('sources') or [])}\n"
        f"Confidence: {finding.get('confidence', '')}\n"
    )


def _parse_response(raw: str) -> Optional[Dict[str, Any]]:
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if "fp_probability" not in parsed:
        return None
    try:
        parsed["fp_probability"] = max(0.0, min(1.0, float(parsed["fp_probability"])))
    except (TypeError, ValueError):
        return None
    return parsed


def triage_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return [{"finding_id", "title", "fp_probability", "reason"}, ...] for
    each finding Ollama could classify. Empty list if USE_AI is off, Ollama
    is unreachable, or there's nothing to triage - never raises."""
    if not _ai_enabled() or not findings:
        return []

    try:
        from ai_engine.providers import OllamaProvider
    except ImportError:
        return []

    provider = OllamaProvider()
    if not provider.is_available():
        logger.warning("USE_AI is enabled but Ollama is not reachable at %s", provider.base_url)
        return []

    model = os.getenv("LOCAL_LLM_MODEL", "llama3.3:70b")
    results = []
    for finding in findings:
        try:
            raw = provider.chat_completion(
                model, [{"role": "user", "content": _build_prompt(finding)}],
                max_tokens=200, temperature=0.1,
            )
            parsed = _parse_response(raw)
        except Exception as e:
            logger.warning("Triage failed for finding %r: %s", finding.get("title"), e)
            continue
        if parsed:
            results.append({
                "finding_id": finding.get("id") or finding.get("finding_id"),
                "title": finding.get("title"),
                "fp_probability": parsed["fp_probability"],
                "reason": parsed.get("reason", ""),
            })
    return results
