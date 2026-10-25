# HackPilot core module
import base64

import bcrypt
import pytest
from advance_hackpilot import EnterpriseHackPilot, EnterpriseWebDashboard

def test_enterprise_web_dashboard_initialization():
    app_instance = EnterpriseHackPilot()
    dashboard = EnterpriseWebDashboard(app_instance)
    assert dashboard.hackpilot == app_instance
    assert dashboard.app is not None


def test_healthz_route_is_registered():
    dashboard = EnterpriseWebDashboard(EnterpriseHackPilot())
    client = dashboard.app.test_client()
    resp = client.get("/healthz")
    assert resp.status_code == 200


def test_dashboard_enforces_basic_auth_once_console_auth_user_is_set(monkeypatch):
    pw_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
    monkeypatch.setenv("CONSOLE_AUTH_USER", "analyst")
    monkeypatch.setenv("CONSOLE_AUTH_PASS_HASH", pw_hash)
    monkeypatch.setenv("CONSOLE_ALLOWED_IPS", "127.0.0.1")

    dashboard = EnterpriseWebDashboard(EnterpriseHackPilot())
    client = dashboard.app.test_client()

    denied = client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    assert denied.status_code == 401

    token = base64.b64encode(b"analyst:correct-password").decode()
    allowed = client.get(
        "/",
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        headers={"Authorization": f"Basic {token}"},
    )
    assert allowed.status_code == 200
