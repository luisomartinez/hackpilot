# HackPilot core module
"""Sprint 2: ALLOWED_TARGETS gate for active exploitation."""

from security.target_allowlist import is_target_allowed


def test_fails_closed_when_unset(monkeypatch):
    monkeypatch.delenv("ALLOWED_TARGETS", raising=False)
    assert is_target_allowed("https://x.com") is False


def test_exact_hostname_match(monkeypatch):
    monkeypatch.setenv("ALLOWED_TARGETS", "x.com,y.com")
    assert is_target_allowed("https://x.com/path") is True
    assert is_target_allowed("z.com") is False


def test_wildcard_subdomain_match(monkeypatch):
    monkeypatch.setenv("ALLOWED_TARGETS", "*.x.com")
    assert is_target_allowed("https://api.x.com") is True
    assert is_target_allowed("https://x.com") is True
    assert is_target_allowed("https://notx.com") is False


def test_cidr_match(monkeypatch):
    monkeypatch.setenv("ALLOWED_TARGETS", "10.0.0.0/24")
    assert is_target_allowed("10.0.0.5") is True
    assert is_target_allowed("10.0.1.5") is False


def test_empty_target_is_never_allowed(monkeypatch):
    monkeypatch.setenv("ALLOWED_TARGETS", "x.com")
    assert is_target_allowed("") is False
