# HackPilot core module
"""Pytest root config — stub heavy deps before hackpilot.py is imported."""

import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _stub(name: str) -> types.ModuleType:
    if name not in sys.modules:
        sys.modules[name] = types.ModuleType(name)
    return sys.modules[name]


# NOTE: these are unconditionally stubbed (not "only if missing real import")
# on purpose - several existing tests depend on the *blank* stand-in rather
# than whatever version happens to be installed on the host (e.g. the real
# `kubernetes`/`jwt` clients behave differently enough from a blank module to
# change test outcomes). bcrypt, flask and flask_cors are deliberately left
# off this list: they're genuinely installed, nothing here relied on them
# being blanked, and Sprint 0's dashboard auth tests need the real Flask
# app/test_client/bcrypt.checkpw behavior, not a MagicMock standing in.
for _mod in (
    "openai",
    "speech_recognition",
    "pyttsx3",
    "pypandoc",
    "cvsslib",
    "redis",
    "psycopg2",
    "sqlalchemy",
    "celery",
    "docker",
    "kubernetes",
    "consul",
    "jwt",
    "ldap3",
    "numpy",
    "pandas",
    "seaborn",
    "websockets",
    "aiohttp",
    "requests",
):
    _stub(_mod)

# Populate sys.modules with the real package when it's actually installed,
# so _stub("flask")/_stub("flask_cors") below return it instead of creating
# a blank stand-in (bcrypt gets the same treatment implicitly - it was never
# added to the blanket-stub loop above).
for _real_mod in ("flask", "flask_cors"):
    try:
        __import__(_real_mod)
    except ImportError:
        pass


def _fill_missing(mod: types.ModuleType, **attrs) -> None:
    """Set each attribute only if the module doesn't already provide it -
    so a real, installed library is never clobbered by a mock."""
    for name, value in attrs.items():
        if not hasattr(mod, name):
            setattr(mod, name, value)


_fill_missing(
    _stub("flask"),
    Flask=MagicMock(), render_template=MagicMock(), request=MagicMock(),
    jsonify=MagicMock(), session=MagicMock(), Response=MagicMock(),
)
_fill_missing(_stub("flask_cors"), CORS=MagicMock())
_fill_missing(_stub("celery"), Celery=MagicMock())
_fill_missing(_stub("ldap3"), Server=MagicMock(), Connection=MagicMock(), ALL=MagicMock())

matplotlib = _stub("matplotlib")
_fill_missing(matplotlib, use=MagicMock())
_stub("matplotlib.pyplot")
_fill_missing(_stub("sklearn.cluster"), DBSCAN=MagicMock())
_fill_missing(_stub("sklearn.ensemble"), IsolationForest=MagicMock())

_internal = {
    "database": [
        "get_db_manager",
        "PentestSession",
        "Vulnerability",
        "User",
        "AuditLog",
        "AIContext",
    ],
    "security": [
        "EnterpriseAuth", "ComplianceFrameworkMapper", "get_soc_analyzer",
        "AdvancedSOCAnalyzer", "ThreatSeverity", "LogFormat", "SOCAlert",
        "NormalizedLogEntry", "IOCResult", "AnomalyResult", "IncidentTimeline",
        "Playbook", "SOCAnalysisReport", "SIEMConnectorType", "SIEMConnector",
        "SplunkConnector", "QRadarConnector", "ElasticsearchConnector",
        "WebhookConnector", "SIEMConnectorManager"
    ],
    "exploitation": ["AdvancedExploitationEngine", "ZeroDayDetector"],
    "reporting": ["DynamicReportGenerator", "get_realtime_dashboard"],
    "cloud": ["DockerManager", "KubernetesManager", "ServiceRegistry"],
    "performance": ["get_cache_manager", "get_parallel_processor"],
}
for pkg, names in _internal.items():
    try:
        # Try importing the real package if it exists locally
        import importlib
        mod = importlib.import_module(pkg)
    except ImportError:
        mod = _stub(pkg)
    for sym in names:
        if not hasattr(mod, sym):
            setattr(mod, sym, MagicMock())


# The real .env in this repo's lab (CONSOLE_AUTH_USER, ALLOWED_TARGETS,
# ENABLE_*_PLUGIN, ...) gets loaded into this *process's* os.environ via
# python-dotenv at import time (see advance_hackpilot.py's Config class),
# same mechanism for every test in this file's process - not a per-test
# leak. Confirmed flaky live: adding ENABLE_NIKTO_JSON_PLUGIN=true etc. to
# .env for a real validation run made unrelated phase3 tests fail, because
# they picked up those flags from the real environment instead of running
# in isolation. Clear every lab-specific flag before each test; tests that
# want one on set it explicitly via monkeypatch.setenv().
_LAB_ENV_PREFIXES = ("ENABLE_", "ALLOWED_TARGETS", "CONSOLE_AUTH_", "CONSOLE_ALLOWED_IPS", "VULNERS_API_KEY", "WPSCAN_API_TOKEN")


@pytest.fixture(autouse=True)
def _isolate_lab_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith(_LAB_ENV_PREFIXES) or key in _LAB_ENV_PREFIXES:
            monkeypatch.delenv(key, raising=False)


