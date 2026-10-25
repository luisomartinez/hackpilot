#!/usr/bin/env python3
# HackPilot core module
"""Target allowlist gate for active exploitation (Sprint 2: sqlmap/ffuf/msf).

Phases 1-3 (recon/enumeration/passive vuln scanning) run unconditionally
against whatever target the operator submits, same as before this sprint.
Phase 4's *active* exploitation tools are a materially bigger blast radius
(SQLMap issuing real injected queries, Metasploit auxiliary checks), so
they get an extra gate on top of the existing ENABLE_AUTO_EXPLOIT /
ENABLE_ADVANCED_EXPLOITATION flags: the target's host must also appear in
ALLOWED_TARGETS.

Fails closed: if ALLOWED_TARGETS is unset or empty, nothing is allowed.
An operator turning on active exploitation for the first time has to
explicitly list what it may run against - there is no implicit "allow
everything" default for this specific gate.
"""

import ipaddress
import os
from typing import List
from urllib.parse import urlparse


def _extract_host(target: str) -> str:
    """Same normalization _extract_scan_host() in advance_hackpilot.py
    uses, duplicated here (not imported) to avoid a security -> main
    module circular import."""
    target = (target or "").strip()
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    return target.split("/", 1)[0].split(":", 1)[0].lower()


def _allowed_entries() -> List[str]:
    raw = os.getenv("ALLOWED_TARGETS", "")
    return [entry.strip().lower() for entry in raw.split(",") if entry.strip()]


def is_target_allowed(target: str) -> bool:
    """True if `target`'s host matches an ALLOWED_TARGETS entry.

    Entries may be an exact hostname/IP, a `*.domain.tld` wildcard for
    subdomains, or a CIDR block for IPs.
    """
    entries = _allowed_entries()
    if not entries:
        return False

    host = _extract_host(target)
    if not host:
        return False

    for entry in entries:
        if "/" in entry:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        elif entry.startswith("*."):
            suffix = entry[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
        elif host == entry:
            return True
    return False
