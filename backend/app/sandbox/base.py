"""Sandbox engine base interface and exceptions (Architecture §5, ADR-002)."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

from app.core.errors import SecureScanException, ErrorCode


class SandboxUnavailableError(SecureScanException):
    """Raised when no secure sandbox engine is available (fail-closed in production)."""
    def __init__(self, message: str = "No secure sandbox engine available. Scan rejected to prevent unsandboxed execution."):
        super().__init__(
            code=ErrorCode.ERR_SANDBOX_UNAVAILABLE,
            message=message,
            status_code=500
        )


class SandboxEngine(ABC):
    """
    Abstract contract for sandbox execution engines.
    Three concrete implementations: DockerSandbox, BubblewrapSandbox, SubprocessDevSandbox.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Engine name identifier (e.g. docker, bubblewrap, subprocess-dev)."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether prerequisites for this sandbox engine exist on host."""
        pass

    @abstractmethod
    def execute(
        self,
        cmd: list[str],
        worktree_dir: Path,
        timeout_seconds: Optional[int] = None,
        limits_override: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, str, str, int]:
        """
        Execute command inside the sandbox.
        Returns: (exit_code, stdout, stderr, duration_ms)
        """
        pass
