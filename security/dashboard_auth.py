#!/usr/bin/env python3
# HackPilot core module
"""Console-facing auth gate for HackPilot's web dashboard (:8080).

This is deliberately separate from security.authentication.EnterpriseAuth
(RBAC/JWT/LDAP), which authorizes pentest *scope* via --auth-key and has
nothing to do with who may open the dashboard UI. This module answers a
narrower question: can this HTTP client reach the console at all.

Two independent, additive gates, both controlled from .env:
  - CONSOLE_ALLOWED_IPS: CSV of IPs/CIDRs allowed to reach the dashboard
    (default "127.0.0.1").
  - CONSOLE_AUTH_USER / CONSOLE_AUTH_PASS_HASH (bcrypt): if set, every
    request must also present matching HTTP Basic credentials.

Safe-by-default fallback: if CONSOLE_AUTH_USER is not configured, the
dashboard process binds to 127.0.0.1 only (see resolve_dashboard_host),
so it is unreachable off-box even though the IP allowlist alone would
otherwise be the only gate in front of it.
"""

import ipaddress
import logging
import os
from typing import List, Optional

import bcrypt
from flask import Flask, Response, request

logger = logging.getLogger("hackpilot.dashboard_auth")

# Routes Docker's own healthcheck (curl from inside the container) must
# always be able to reach, regardless of IP allowlist or Basic Auth.
EXEMPT_PATHS = {"/healthz"}


def _allowed_ips() -> List[str]:
    raw = os.getenv("CONSOLE_ALLOWED_IPS", "127.0.0.1")
    return [entry.strip() for entry in raw.split(",") if entry.strip()]


def _is_ip_allowed(remote_addr: Optional[str], allowed: List[str]) -> bool:
    if not remote_addr:
        return False
    try:
        client_ip = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False

    for entry in allowed:
        try:
            if "/" in entry:
                if client_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif client_ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def resolve_dashboard_host() -> str:
    """Bind address for the dashboard's own app.run(host=...) call."""
    return "0.0.0.0" if os.getenv("CONSOLE_AUTH_USER") else "127.0.0.1"


def _unauthorized() -> Response:
    return Response(
        "Authentication required",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="HackPilot Console"'},
    )


def init_dashboard_auth(app: Flask) -> None:
    """Register the IP allowlist + optional Basic Auth before_request hook."""
    auth_user = os.getenv("CONSOLE_AUTH_USER")
    auth_pass_hash = os.getenv("CONSOLE_AUTH_PASS_HASH")

    if not auth_user:
        logger.warning(
            "CONSOLE_AUTH_USER not set - dashboard Basic Auth is disabled and "
            "the process will bind to 127.0.0.1 only. Set CONSOLE_AUTH_USER / "
            "CONSOLE_AUTH_PASS_HASH / CONSOLE_ALLOWED_IPS in .env to allow "
            "authenticated remote access."
        )
    elif not auth_pass_hash:
        logger.error(
            "CONSOLE_AUTH_USER is set but CONSOLE_AUTH_PASS_HASH is missing - "
            "every request will be rejected until both are configured."
        )

    @app.route("/healthz")
    def _dashboard_healthz():
        return {"status": "ok"}

    @app.before_request
    def _dashboard_auth_gate():
        if request.path in EXEMPT_PATHS:
            return None

        if not _is_ip_allowed(request.remote_addr, _allowed_ips()):
            logger.warning("Blocked dashboard request from disallowed IP %s", request.remote_addr)
            return Response("Forbidden", status=403)

        if not auth_user:
            return None  # no credentials configured - IP allowlist is the only gate

        creds = request.authorization
        if not creds or creds.username != auth_user or not auth_pass_hash:
            return _unauthorized()

        try:
            if not bcrypt.checkpw(creds.password.encode("utf-8"), auth_pass_hash.encode("utf-8")):
                return _unauthorized()
        except ValueError:
            logger.error("CONSOLE_AUTH_PASS_HASH is not a valid bcrypt hash")
            return _unauthorized()

        return None
