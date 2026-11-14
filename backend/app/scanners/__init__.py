"""Scanner adapters registry."""
from app.scanners.base import BaseScannerAdapter, ScannerMetadata, RawFinding, ScannerExecutionResult
from app.scanners.runner import build_sandbox_docker_cmd, execute_sandboxed_command, strip_terminal_escapes
from app.scanners.gitleaks import GitleaksAdapter
from app.scanners.semgrep import SemgrepAdapter
from app.scanners.osv import OsvScannerAdapter
from app.scanners.bandit import BanditAdapter

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
    "BanditAdapter"
]
