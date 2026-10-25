#!/usr/bin/env python3
# HackPilot core module
"""Heuristic CVSS v3.1 vector/score estimation for findings.

None of our tool runners (sqlmap/nuclei/testssl/wapiti/ffuf/nikto/...)
report a CVSS vector themselves - they report a title and a rough
severity bucket. This maps a handful of recognizable finding patterns to
a representative CVSS 3.1 vector, falling back to a generic vector for
the finding's existing severity bucket when nothing more specific
matches. These are estimates for triage/prioritization, not an exact
score for a specific instance of the finding.
"""

import logging
import re
from typing import Tuple

logger = logging.getLogger("hackpilot.reporting.cvss_heuristics")

try:
    from cvss import CVSS3
    _CVSS_AVAILABLE = True
except ImportError:
    _CVSS_AVAILABLE = False

# (pattern over the finding title, CVSS 3.1 vector) - checked in order,
# first match wins.
_HEURISTIC_VECTORS = [
    (re.compile(r"sql injection", re.I), "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (re.compile(r"\bxss\b|cross[- ]site scripting", re.I), "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    (re.compile(r"tls ?1\.0|sslv[23]|\bbeast\b|\bpoodle\b|\bdrown\b|\bheartbleed\b", re.I), "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
]

# Generic fallback by severity bucket when no title pattern matches.
_SEVERITY_FALLBACK_VECTORS = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "medium": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "low": "AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    "info": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

# Static scores for the fallback vectors above, used only when the `cvss`
# package isn't installed - keeps cvss_score populated instead of 0.0.
_SEVERITY_FALLBACK_SCORES = {
    "critical": 9.8,
    "high": 7.5,
    "medium": 5.3,
    "low": 2.6,
    "info": 0.0,
}


def _score_vector(vector: str, severity: str) -> float:
    if not _CVSS_AVAILABLE:
        return _SEVERITY_FALLBACK_SCORES.get((severity or "info").lower(), 0.0)
    try:
        return CVSS3(f"CVSS:3.1/{vector}").scores()[0]
    except Exception as e:
        logger.warning("Could not score CVSS vector %r: %s", vector, e)
        return _SEVERITY_FALLBACK_SCORES.get((severity or "info").lower(), 0.0)


def estimate_cvss(title: str, severity: str = "info") -> Tuple[str, float]:
    """Return (full "CVSS:3.1/..." vector string, base score)."""
    for pattern, vector in _HEURISTIC_VECTORS:
        if pattern.search(title or ""):
            return f"CVSS:3.1/{vector}", _score_vector(vector, severity)

    vector = _SEVERITY_FALLBACK_VECTORS.get((severity or "info").lower(), _SEVERITY_FALLBACK_VECTORS["info"])
    return f"CVSS:3.1/{vector}", _score_vector(vector, severity)
