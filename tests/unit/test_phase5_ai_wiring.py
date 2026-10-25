# HackPilot core module
"""Sprint 3.5: phase5_reporting wires in AI triage/narrative only when
USE_AI is enabled, and never otherwise."""

import json
from datetime import datetime
from types import SimpleNamespace

import ai_engine.providers as providers_module
from advance_hackpilot import EnterprisePentestingPhases


class FakeOllamaProvider:
    def __init__(self):
        self.calls = 0

    def is_available(self):
        return True

    def chat_completion(self, model, messages, max_tokens=4096, temperature=0.7):
        self.calls += 1
        if "attack chain" in messages[0]["content"].lower():
            return "The attacker chains the SQLi into full database access."
        return json.dumps({"fp_probability": 0.1, "reason": "confirmed by sqlmap"})


class FakeReportGenerator:
    def generate_technical_report(self, session_data):
        return "report text"


class FakeDB:
    def __init__(self, vulns):
        self._vulns = vulns
        self.ai_contexts = []

    def get_pentest_session(self, session_id):
        return SimpleNamespace(target="x.com", scope="web", created_at=datetime.utcnow())

    def get_vulnerabilities_by_session(self, session_id):
        return self._vulns

    def get_phase_results(self, session_id):
        return []

    def save_ai_context(self, session_id, context_type, context_data, confidence_score=None):
        self.ai_contexts.append((context_type, context_data))
        return f"ctx-{len(self.ai_contexts)}"

    def create_vulnerability(self, **kwargs):
        return "vuln-report"

    def create_phase_result(self, **kwargs):
        return "phase-5"

    def update_phase_result(self, **kwargs):
        pass


def _vuln(id_, title, severity="critical", validated=True, sources=None):
    return SimpleNamespace(
        id=id_, title=title, severity=severity, proof_of_concept="https://x.com/item?id=1",
        description="desc", remediation="fix it", cvss_score=9.8, cvss_vector="CVSS:3.1/...",
        sources=sources or ["sqlmap"], validated=validated, confidence="high", evidence={},
    )


def _phases(db):
    phases = EnterprisePentestingPhases(
        session_id="s1", ai_engine=None, tool_manager=None, target_info={"target": "https://x.com"},
        db=db, cache=None, processor=None, exploitation=None, zero_day_detector=None,
        compliance=None, report_generator=FakeReportGenerator(),
    )
    return phases


def test_ai_wiring_is_skipped_when_use_ai_disabled(monkeypatch):
    monkeypatch.delenv("USE_AI", raising=False)
    db = FakeDB([_vuln("v1", "SQL Injection confirmed")])
    _phases(db).phase5_reporting()
    assert db.ai_contexts == []


def test_ai_wiring_caches_triage_and_narrative_when_enabled(monkeypatch):
    monkeypatch.setenv("USE_AI", "true")
    monkeypatch.setattr(providers_module, "OllamaProvider", FakeOllamaProvider)

    db = FakeDB([_vuln("v1", "SQL Injection confirmed")])
    _phases(db).phase5_reporting()

    context_types = {c[0] for c in db.ai_contexts}
    assert context_types == {"triage", "attack_chain_narrative"}
    triage_data = next(c[1] for c in db.ai_contexts if c[0] == "triage")
    assert triage_data["results"][0]["finding_id"] == "v1"
