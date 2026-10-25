# HackPilot core module
"""Sprint 3.5: local-only AI triage + attack-chain narrative.

Both must no-op (return [] / None) whenever USE_AI is off, Ollama is
unreachable, or there's nothing to act on - and must never import/call
anything other than ai_engine.providers.OllamaProvider.
"""

import json

import ai_engine.providers as providers_module
from ai_engine.attack_narrative import generate_attack_narrative, save_attack_narrative
from ai_engine.triage import triage_findings


class FakeOllamaProvider:
    def __init__(self, available=True, response="", base_url="http://localhost:11434"):
        self.available = available
        self.response = response
        self.base_url = base_url
        self.calls = []

    def is_available(self):
        return self.available

    def chat_completion(self, model, messages, max_tokens=4096, temperature=0.7):
        self.calls.append((model, messages))
        return self.response


# ------------------------------------------------------------------ triage ---

def test_triage_returns_empty_when_use_ai_disabled(monkeypatch):
    monkeypatch.delenv("USE_AI", raising=False)
    assert triage_findings([{"title": "x"}]) == []


def test_triage_returns_empty_when_ollama_unreachable(monkeypatch):
    monkeypatch.setenv("USE_AI", "true")
    monkeypatch.setattr(providers_module, "OllamaProvider", lambda: FakeOllamaProvider(available=False))
    assert triage_findings([{"title": "x"}]) == []


def test_triage_parses_json_response_per_finding(monkeypatch):
    monkeypatch.setenv("USE_AI", "true")
    fake = FakeOllamaProvider(response=json.dumps({"fp_probability": 0.2, "reason": "matches known pattern"}))
    monkeypatch.setattr(providers_module, "OllamaProvider", lambda: fake)

    results = triage_findings([{"id": "v1", "title": "SQL Injection confirmed", "sources": ["sqlmap"]}])
    assert results == [{"finding_id": "v1", "title": "SQL Injection confirmed", "fp_probability": 0.2, "reason": "matches known pattern"}]


def test_triage_skips_findings_with_unparseable_response(monkeypatch):
    monkeypatch.setenv("USE_AI", "true")
    fake = FakeOllamaProvider(response="not json at all")
    monkeypatch.setattr(providers_module, "OllamaProvider", lambda: fake)
    assert triage_findings([{"id": "v1", "title": "x"}]) == []


def test_triage_clamps_out_of_range_probability(monkeypatch):
    monkeypatch.setenv("USE_AI", "true")
    fake = FakeOllamaProvider(response=json.dumps({"fp_probability": 5.0, "reason": "oops"}))
    monkeypatch.setattr(providers_module, "OllamaProvider", lambda: fake)
    [result] = triage_findings([{"id": "v1", "title": "x"}])
    assert result["fp_probability"] == 1.0


def test_triage_returns_empty_with_no_findings(monkeypatch):
    monkeypatch.setenv("USE_AI", "true")
    assert triage_findings([]) == []


# --------------------------------------------------------------- narrative --

def test_narrative_returns_none_when_use_ai_disabled(monkeypatch):
    monkeypatch.delenv("USE_AI", raising=False)
    assert generate_attack_narrative([{"title": "x", "validated": True}]) is None


def test_narrative_returns_none_without_validated_findings(monkeypatch):
    monkeypatch.setenv("USE_AI", "true")
    assert generate_attack_narrative([{"title": "x", "validated": False}]) is None


def test_narrative_returns_none_when_ollama_unreachable(monkeypatch):
    monkeypatch.setenv("USE_AI", "true")
    monkeypatch.setattr(providers_module, "OllamaProvider", lambda: FakeOllamaProvider(available=False))
    assert generate_attack_narrative([{"title": "x", "validated": True}]) is None


def test_narrative_returns_stripped_text_from_ollama(monkeypatch):
    monkeypatch.setenv("USE_AI", "true")
    fake = FakeOllamaProvider(response="  The attacker could chain X into Y.  ")
    monkeypatch.setattr(providers_module, "OllamaProvider", lambda: fake)

    narrative = generate_attack_narrative([{"title": "SQLi", "severity": "critical", "validated": True, "sources": ["sqlmap"]}])
    assert narrative == "The attacker could chain X into Y."
    assert fake.calls  # it actually asked the model


def test_save_attack_narrative_writes_markdown_file(tmp_path):
    out_dir = tmp_path / "output" / "post"
    path = save_attack_narrative("# Attack Chain\n\nSome text.", output_dir=str(out_dir))
    assert path == str(out_dir / "attack_chain.md")
    assert (out_dir / "attack_chain.md").read_text(encoding="utf-8") == "# Attack Chain\n\nSome text."
