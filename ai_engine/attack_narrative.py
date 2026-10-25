#!/usr/bin/env python3
# HackPilot core module
"""Local-only attack-chain narrative over confirmed findings (Sprint 3.5).

Deliberately separate from ai_engine.attack_chainer.AttackChainingEngine,
which already synthesizes a graph-based attack chain (MITRE ATT&CK
mapping, Mermaid diagram) without any LLM - that stays the structural
source of truth. This module asks a local Ollama model to narrate, in
prose, the most likely path through this session's *validated* findings
and the worst-case impact - a plain-language summary for the report, not
a replacement for the graph.

Same USE_AI/LOCAL_LLM_ENDPOINT/LOCAL_LLM_MODEL gating as ai_engine.triage:
no call is ever made to a non-local/non-Ollama provider.
"""

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hackpilot.ai_engine.attack_narrative")


def _ai_enabled() -> bool:
    return os.getenv("USE_AI", "false").strip().lower() == "true"


def _build_prompt(findings: List[Dict[str, Any]]) -> str:
    lines = [
        f"- {f.get('severity', 'info').upper()}: {f.get('title', '')} "
        f"(target: {f.get('target', f.get('proof_of_concept', ''))}, "
        f"sources: {', '.join(f.get('sources') or [])})"
        for f in findings
    ]
    return (
        "You are a penetration tester writing the attack-chain section of a "
        "report. Given these CONFIRMED findings from one assessment, describe "
        "in 3-5 short paragraphs the most likely attack chain an adversary "
        "could build from them, and the maximum realistic impact. Be concrete "
        "about which finding enables which next step. Do not invent findings "
        "not listed below.\n\nConfirmed findings:\n" + "\n".join(lines)
    )


def generate_attack_narrative(findings: List[Dict[str, Any]]) -> Optional[str]:
    """Returns a markdown narrative, or None if USE_AI is off, Ollama is
    unreachable, or there are no validated findings to narrate."""
    if not _ai_enabled():
        return None

    confirmed = [f for f in findings if f.get("validated")]
    if not confirmed:
        return None

    try:
        from ai_engine.providers import OllamaProvider
    except ImportError:
        return None

    provider = OllamaProvider()
    if not provider.is_available():
        logger.warning("USE_AI is enabled but Ollama is not reachable at %s", provider.base_url)
        return None

    model = os.getenv("LOCAL_LLM_MODEL", "llama3.3:70b")
    try:
        narrative = provider.chat_completion(
            model, [{"role": "user", "content": _build_prompt(confirmed)}],
            max_tokens=800, temperature=0.4,
        )
    except Exception as e:
        logger.warning("Attack narrative generation failed: %s", e)
        return None

    return narrative.strip() if narrative else None


def save_attack_narrative(narrative: str, output_dir: str = "output/post") -> str:
    """Writes the narrative to <output_dir>/attack_chain.md, returns the path."""
    from pathlib import Path
    out_path = Path(output_dir) / "attack_chain.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(narrative, encoding="utf-8")
    return str(out_path)
