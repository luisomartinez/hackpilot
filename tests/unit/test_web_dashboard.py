# HackPilot core module
import base64

import bcrypt
import pytest
from advance_hackpilot import EnterpriseHackPilot, EnterpriseWebDashboard, cancellation_registry

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


class _FakeDB:
    def update_session_status(self, session_id, status, updated_by):
        self.last_status = (session_id, status, updated_by)


class _FakeToolManager:
    def __init__(self):
        self.terminate_called = False

    def terminate_active_process(self):
        self.terminate_called = True


def test_cancel_route_requests_cancellation_and_kills_the_active_process(monkeypatch):
    """Regression test for the real bug: /cancel used to only update the
    session's DB status, leaving whatever tool was running (confirmed
    live against doblefactor.co: amass, then whatweb) going for minutes
    afterward. It must now also flag the session as cancelled in the
    registry and kill the in-flight subprocess immediately."""
    # This process's actual .env (CONSOLE_AUTH_USER=admin) is loaded into
    # os.environ at import time, unrelated to this test's auth posture -
    # force it off so the route under test isn't gated by Basic Auth.
    monkeypatch.delenv("CONSOLE_AUTH_USER", raising=False)
    monkeypatch.delenv("CONSOLE_AUTH_PASS_HASH", raising=False)

    app_instance = EnterpriseHackPilot()
    app_instance.db = _FakeDB()
    app_instance.tool_manager = _FakeToolManager()
    dashboard = EnterpriseWebDashboard(app_instance)
    client = dashboard.app.test_client()

    session_id = "session-under-test"
    cancellation_registry.clear(session_id)
    try:
        resp = client.post(f"/api/session/{session_id}/cancel")
        assert resp.status_code == 200
        assert cancellation_registry.is_requested(session_id) is True
        assert app_instance.tool_manager.terminate_called is True
        assert app_instance.db.last_status == (session_id, "cancelled", "system")
    finally:
        cancellation_registry.clear(session_id)
