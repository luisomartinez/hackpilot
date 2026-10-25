# HackPilot core module
"""Sprint 0.1: console auth gate (security/dashboard_auth.py).

CONSOLE_AUTH_USER / CONSOLE_AUTH_PASS_HASH / CONSOLE_ALLOWED_IPS are read once
when init_dashboard_auth(app) registers its before_request hook, so each test
builds its own Flask app after setting the env vars it needs.
"""

import base64

import bcrypt
import pytest
from flask import Flask

from security.dashboard_auth import init_dashboard_auth, resolve_dashboard_host


def _build_app():
    app = Flask(__name__)
    init_dashboard_auth(app)

    @app.route("/")
    def index():
        return "ok"

    return app.test_client()


def _basic_auth_header(username: str, password: str) -> dict:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_no_credentials_configured_allows_default_loopback(monkeypatch):
    monkeypatch.delenv("CONSOLE_AUTH_USER", raising=False)
    monkeypatch.delenv("CONSOLE_AUTH_PASS_HASH", raising=False)
    monkeypatch.delenv("CONSOLE_ALLOWED_IPS", raising=False)
    client = _build_app()

    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    assert resp.status_code == 200


def test_ip_not_in_allowlist_is_forbidden(monkeypatch):
    monkeypatch.delenv("CONSOLE_AUTH_USER", raising=False)
    monkeypatch.setenv("CONSOLE_ALLOWED_IPS", "127.0.0.1")
    client = _build_app()

    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.9"})
    assert resp.status_code == 403


def test_credentials_configured_without_header_is_unauthorized(monkeypatch):
    pw_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
    monkeypatch.setenv("CONSOLE_AUTH_USER", "analyst")
    monkeypatch.setenv("CONSOLE_AUTH_PASS_HASH", pw_hash)
    monkeypatch.setenv("CONSOLE_ALLOWED_IPS", "127.0.0.1")
    client = _build_app()

    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    assert resp.status_code == 401
    assert "Basic" in resp.headers.get("WWW-Authenticate", "")


def test_correct_credentials_are_authorized(monkeypatch):
    pw_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
    monkeypatch.setenv("CONSOLE_AUTH_USER", "analyst")
    monkeypatch.setenv("CONSOLE_AUTH_PASS_HASH", pw_hash)
    monkeypatch.setenv("CONSOLE_ALLOWED_IPS", "127.0.0.1")
    client = _build_app()

    resp = client.get(
        "/",
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        headers=_basic_auth_header("analyst", "correct-password"),
    )
    assert resp.status_code == 200


def test_wrong_password_is_unauthorized(monkeypatch):
    pw_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
    monkeypatch.setenv("CONSOLE_AUTH_USER", "analyst")
    monkeypatch.setenv("CONSOLE_AUTH_PASS_HASH", pw_hash)
    monkeypatch.setenv("CONSOLE_ALLOWED_IPS", "127.0.0.1")
    client = _build_app()

    resp = client.get(
        "/",
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        headers=_basic_auth_header("analyst", "wrong-password"),
    )
    assert resp.status_code == 401


def test_healthz_is_exempt_from_ip_and_auth(monkeypatch):
    pw_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
    monkeypatch.setenv("CONSOLE_AUTH_USER", "analyst")
    monkeypatch.setenv("CONSOLE_AUTH_PASS_HASH", pw_hash)
    monkeypatch.setenv("CONSOLE_ALLOWED_IPS", "127.0.0.1")
    client = _build_app()

    resp = client.get("/healthz", environ_overrides={"REMOTE_ADDR": "203.0.113.9"})
    assert resp.status_code == 200


def test_resolve_dashboard_host_defaults_to_loopback(monkeypatch):
    monkeypatch.delenv("CONSOLE_AUTH_USER", raising=False)
    assert resolve_dashboard_host() == "127.0.0.1"


def test_resolve_dashboard_host_opens_up_once_auth_user_is_set(monkeypatch):
    monkeypatch.setenv("CONSOLE_AUTH_USER", "analyst")
    assert resolve_dashboard_host() == "0.0.0.0"
