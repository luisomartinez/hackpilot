# HackPilot core module
"""Sprint 3.2: per-finding evidence persistence."""

import json
import os

from reporting.evidence_store import save_evidence


def test_save_evidence_always_writes_evidence_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    finding = {
        "title": "Subdomain discovered: api.x.com",
        "target": "api.x.com",
        "sources": ["subfinder", "amass"],
        "confidence": "info",
        "evidence": {"subfinder": {"subdomain": "api.x.com"}, "amass": {"subdomain": "api.x.com"}},
    }
    out_dir = save_evidence("sess1", "vuln1", finding)

    assert out_dir == os.path.join("evidence", "sess1", "vuln1")
    data = json.loads((tmp_path / out_dir / "evidence.json").read_text())
    assert data == finding["evidence"]
    assert (tmp_path / out_dir / "reproduction_steps.txt").exists()


def test_save_evidence_extracts_wapiti_http_request(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    finding = {
        "title": "SQL Injection: id param",
        "target": "https://x.com/a?id=1",
        "sources": ["wapiti"],
        "confidence": "medium",
        "evidence": {"wapiti": {"http_request": "GET /a?id=1 HTTP/1.1\nHost: x.com"}},
    }
    out_dir = save_evidence("sess1", "vuln2", finding)
    assert (tmp_path / out_dir / "request.http").read_text() == "GET /a?id=1 HTTP/1.1\nHost: x.com"
    assert not (tmp_path / out_dir / "response.http").exists()


def test_save_evidence_extracts_nuclei_request_and_response(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    finding = {
        "title": "Exposed Panel",
        "target": "https://x.com/admin",
        "sources": ["nuclei"],
        "confidence": "medium",
        "evidence": {"nuclei": {"request": "GET /admin HTTP/1.1", "response": "HTTP/1.1 200 OK"}},
    }
    out_dir = save_evidence("sess1", "vuln3", finding)
    assert (tmp_path / out_dir / "request.http").read_text() == "GET /admin HTTP/1.1"
    assert (tmp_path / out_dir / "response.http").read_text() == "HTTP/1.1 200 OK"


def test_save_evidence_without_http_transcript_only_writes_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    finding = {
        "title": "Path found: backup.sql (200)",
        "target": "https://x.com/backup.sql",
        "sources": ["ffuf"],
        "confidence": "medium",
        "evidence": {"ffuf": {"url": "https://x.com/backup.sql", "status": 200}},
    }
    out_dir = save_evidence("sess1", "vuln4", finding)
    assert not (tmp_path / out_dir / "request.http").exists()
    assert not (tmp_path / out_dir / "response.http").exists()
    assert (tmp_path / out_dir / "evidence.json").exists()
