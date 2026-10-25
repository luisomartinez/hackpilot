# HackPilot core module
"""Sprint 0.2: report-at-rest encryption (security/report_crypto.py)."""

import base64
import os

import pytest

from security.report_crypto import (
    decrypt_bytes,
    encrypt_bytes,
    encryption_enabled,
    read_report_file,
    write_report_file,
    write_report_text,
)


def _b64_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def test_encryption_disabled_without_key(monkeypatch):
    monkeypatch.delenv("REPORT_ENCRYPTION_KEY", raising=False)
    assert encryption_enabled() is False


def test_encryption_enabled_with_valid_key(monkeypatch):
    monkeypatch.setenv("REPORT_ENCRYPTION_KEY", _b64_key())
    assert encryption_enabled() is True


def test_malformed_key_disables_encryption(monkeypatch):
    monkeypatch.setenv("REPORT_ENCRYPTION_KEY", "not-valid-base64-or-32-bytes")
    assert encryption_enabled() is False


def test_encrypt_decrypt_roundtrip(monkeypatch):
    monkeypatch.setenv("REPORT_ENCRYPTION_KEY", _b64_key())
    plaintext = b"%PDF-1.7 fake report body for test purposes"
    blob = encrypt_bytes(plaintext)
    assert blob != plaintext
    assert decrypt_bytes(blob) == plaintext


def test_write_report_file_falls_back_to_plaintext_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("REPORT_ENCRYPTION_KEY", raising=False)
    target = tmp_path / "report.pdf"

    written_path = write_report_file(target, b"%PDF-1.7 plain")
    assert written_path == str(target)
    assert target.read_bytes() == b"%PDF-1.7 plain"


def test_write_report_file_encrypts_and_round_trips_with_key(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORT_ENCRYPTION_KEY", _b64_key())
    target = tmp_path / "report.pdf"
    original = b"%PDF-1.7 encrypted report body"

    written_path = write_report_file(target, original)
    assert written_path == str(target) + ".enc"
    assert not target.exists()

    on_disk = open(written_path, "rb").read()
    assert original not in on_disk  # not sitting in plaintext at rest

    assert read_report_file(written_path) == original


def test_write_report_text_matches_write_report_file(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORT_ENCRYPTION_KEY", _b64_key())
    target = tmp_path / "technical_report.txt"

    written_path = write_report_text(target, "line one\nline two")
    assert written_path.endswith(".enc")
    assert read_report_file(written_path).decode("utf-8") == "line one\nline two"
