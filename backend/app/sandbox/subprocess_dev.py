"""Development/test-only subprocess sandbox with production fail-closed enforcement (ADR-002)."""
import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

from app.core.config import settings
from app.core.limits import limits
from app.sandbox.base import SandboxEngine, SandboxUnavailableError

logger = logging.getLogger(__name__)
ANSI_ESCAPE_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_terminal_escapes(text: str) -> str:
    """Sanitize scanner output by stripping terminal color/control sequences."""
    if not text:
        return ""
    return ANSI_ESCAPE_REGEX.sub("", text)


class SubprocessDevSandbox(SandboxEngine):
    """
    Subprocess execution engine for LOCAL DEVELOPMENT AND TESTING ONLY.
    STRICT FAIL-CLOSED POLICY:
    Refuses to execute if ENVIRONMENT == "production" by raising SandboxUnavailableError.
    """

    @property
    def name(self) -> str:
        return "subprocess-dev"

    def is_available(self) -> bool:
        # Refuses availability in production
        if getattr(settings, "ENVIRONMENT", "").lower() == "production":
            return False
        return True

    def execute(
        self,
        cmd: list[str],
        worktree_dir: Path,
        timeout_seconds: Optional[int] = None,
        limits_override: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, str, str, int]:
        # Production fail-closed check
        env_mode = getattr(settings, "ENVIRONMENT", "development").lower()
        if env_mode == "production":
            logger.critical("SECURITY VIOLATION ATTEMPT: SubprocessDevSandbox invoked in production. Failing closed.")
            raise SandboxUnavailableError(
                "Insecure subprocess-dev sandbox engine cannot be executed in production environment. "
                "Fail-closed policy enforced (Architecture §5, ADR-002)."
            )

        logger.warning(
            "*** SECURITY WARNING: Running tool execution via unisolated SubprocessDevSandbox. "
            "Permitted for development and testing only. ***"
        )

        timeout = timeout_seconds or limits.SCANNER_TOOL_TIMEOUT_SECONDS
        start_time = time.time()

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(worktree_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            duration_ms = int((time.time() - start_time) * 1000)
            return (
                proc.returncode,
                strip_terminal_escapes(proc.stdout),
                strip_terminal_escapes(proc.stderr),
                duration_ms
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - start_time) * 1000)
            return -1, "", f"Execution timed out after {timeout} seconds", duration_ms
        except Exception as exc:
            duration_ms = int((time.time() - start_time) * 1000)
            return -2, "", f"Process execution failed: {str(exc)}", duration_ms
