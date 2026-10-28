#!/usr/bin/env python3
# HackPilot core module
"""Plugin interface. See plugins/__init__.py for the registry and the
backward-compatibility/scope-guard rules every plugin must follow."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class PluginContext:
    """Everything a plugin might need, gathered once per phase call so
    individual plugins don't each re-derive it. Mirrors the data already
    available inside EnterprisePentestingPhases at the point each phase
    runs its plugins."""
    tool_manager: Any
    target: str
    scan_host: str
    subdomains: List[str] = field(default_factory=list)
    open_ports: List[str] = field(default_factory=list)
    has_web_service: bool = False
    tech_findings: List[Dict[str, Any]] = field(default_factory=list)

    def tech_names(self) -> List[str]:
        return [t.get("title", "") for t in self.tech_findings]


@dataclass
class PluginResult:
    tool: str
    phase: str
    command: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    raw_output_path: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class Plugin(ABC):
    name: str
    phase: str
    requires: List[str] = []

    def is_applicable(self, ctx: PluginContext) -> bool:
        """Default: always applicable. Override for conditional plugins
        (e.g. WPScan only when WordPress was detected)."""
        return True

    @abstractmethod
    def run(self, ctx: PluginContext) -> PluginResult:
        ...
