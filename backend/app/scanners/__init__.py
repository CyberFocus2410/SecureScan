"""Scanner adapters registry."""
from app.scanners.base import BaseScannerAdapter, ScannerMetadata, RawFinding, ScannerExecutionResult
from app.scanners.runner import build_sandbox_docker_cmd, execute_sandboxed_command, strip_terminal_escapes
from app.scanners.gitleaks import GitleaksAdapter
from app.scanners.semgrep import SemgrepAdapter
from app.scanners.osv import OsvScannerAdapter
from app.scanners.bandit import BanditAdapter
from app.scanners.trufflehog import TruffleHogAdapter
from app.scanners.iac_config import IacConfigScanner
from app.scanners.database_static import DatabaseStaticScanner
from app.scanners.database_runtime import DatabaseRuntimeScanner
from app.scanners.api_security import ApiSecurityScanner
from app.scanners.ai_security import AiSecurityScanner

__all__ = [
    "BaseScannerAdapter",
    "ScannerMetadata",
    "RawFinding",
    "ScannerExecutionResult",
    "build_sandbox_docker_cmd",
    "execute_sandboxed_command",
    "strip_terminal_escapes",
    "GitleaksAdapter",
    "SemgrepAdapter",
    "OsvScannerAdapter",
    "BanditAdapter",
    "TruffleHogAdapter",
    "IacConfigScanner",
    "DatabaseStaticScanner",
    "DatabaseRuntimeScanner",
    "ApiSecurityScanner",
    "AiSecurityScanner",
]
