# HackPilot core module
"""Sprint 1: cross-tool finding consolidation rules."""

from exploitation.findings_consolidator import consolidate


def test_two_active_sources_agreeing_are_validated_high_confidence():
    raw = [
        {"title": "SQLi in id param", "target": "https://x.com/a?id=1", "source": "nuclei",
         "severity": "high", "evidence": {"a": 1}},
        {"title": "sqli in id param", "target": "https://x.com/a", "source": "wapiti",
         "severity": "critical", "evidence": {"b": 2}},
    ]
    [finding] = consolidate(raw)
    assert finding["validated"] is True
    assert finding["confidence"] == "high"
    assert finding["severity"] == "critical"  # highest of the two
    assert finding["sources"] == ["nuclei", "wapiti"]
    assert finding["evidence"] == {"nuclei": {"a": 1}, "wapiti": {"b": 2}}


def test_single_active_source_is_medium_confidence_not_validated():
    raw = [{"title": "Outdated header", "target": "https://x.com", "source": "testssl",
            "severity": "low", "evidence": {}}]
    [finding] = consolidate(raw)
    assert finding["validated"] is False
    assert finding["confidence"] == "medium"


def test_passive_only_sources_are_info_confidence_even_with_two_sources():
    raw = [
        {"title": "Subdomain discovered: api.x.com", "target": "api.x.com", "source": "subfinder",
         "severity": "info", "evidence": {}},
        {"title": "Subdomain discovered: api.x.com", "target": "api.x.com", "source": "amass",
         "severity": "info", "evidence": {}},
    ]
    [finding] = consolidate(raw)
    assert finding["sources"] == ["amass", "subfinder"]
    assert finding["validated"] is False
    assert finding["confidence"] == "info"


def test_normalization_merges_different_casing_and_query_strings():
    raw = [
        {"title": "XSS Found", "target": "HTTPS://X.com/Path?nonce=abc", "source": "nuclei",
         "severity": "medium", "evidence": {}},
        {"title": "xss found", "target": "https://x.com/Path?nonce=zzz", "source": "wapiti",
         "severity": "medium", "evidence": {}},
    ]
    assert len(consolidate(raw)) == 1


def test_different_targets_are_not_merged():
    raw = [
        {"title": "Subdomain discovered: a.x.com", "target": "a.x.com", "source": "subfinder", "severity": "info", "evidence": {}},
        {"title": "Subdomain discovered: b.x.com", "target": "b.x.com", "source": "subfinder", "severity": "info", "evidence": {}},
    ]
    assert len(consolidate(raw)) == 2


def test_empty_input_returns_empty_list():
    assert consolidate([]) == []
    assert consolidate(None) == []
