# HackPilot core module
"""Sprint 3.1: heuristic CVSS vector/score estimation."""

from reporting.cvss_heuristics import estimate_cvss


def test_sql_injection_title_maps_to_critical_vector():
    vector, score = estimate_cvss("SQL Injection confirmed", severity="critical")
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert score == 9.8


def test_xss_title_maps_to_medium_vector():
    vector, score = estimate_cvss("Reflected XSS in search param", severity="medium")
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    assert score == 6.1


def test_tls_title_maps_to_low_vector():
    vector, score = estimate_cvss("TLS: BEAST - vulnerable", severity="low")
    assert vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
    assert round(score, 1) == 3.7


def test_unrecognized_title_falls_back_to_severity_bucket():
    vector, score = estimate_cvss("Some unrelated finding", severity="high")
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    assert score > 0


def test_unknown_severity_falls_back_to_info():
    vector, score = estimate_cvss("Unrelated", severity="made-up-severity")
    assert vector.endswith("C:N/I:N/A:N")
    assert score == 0.0
