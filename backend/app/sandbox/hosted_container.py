"""Hosted PaaS container sandbox engine (Render, Railway, Fly.io, Cloud Run)."""
import logging
import os
import re
import shutil
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


class HostedContainerSandbox(SandboxEngine):
    """
    Sandbox execution engine for PRE-ISOLATED HOSTED PAAS CONTAINERS (Render, Railway, Cloud Run).

    Cloud platforms run application workloads inside ephemeral, unprivileged Linux container
    sandboxes managed by their orchestration layers. Docker-in-Docker or nested Bubblewrap
    is unavailable in these environments.

    This engine leverages the host platform's container isolation boundary to execute
    the pinned primary security scanner binaries safely with strict timeouts, cwd isolation,
    and output sanitization.
    """

    @property
    def name(self) -> str:
        return "hosted-container"

    def is_available(self) -> bool:
        """
        Available when:
        1. Explicitly enabled via settings.SANDBOX_ALLOW_HOSTED_SUBPROCESS == True, OR
        2. Running on Render (os.environ.get("RENDER") == "true"), OR
        3. Explicitly requested via SANDBOX_BACKEND in ("hosted", "hosted-container")
        """
        backend_choice = getattr(settings, "SANDBOX_BACKEND", "").lower()
        if backend_choice in ("hosted", "hosted-container"):
            return True
        if getattr(settings, "SANDBOX_ALLOW_HOSTED_SUBPROCESS", False):
            return True
        if os.environ.get("RENDER", "").lower() == "true":
            return True
        return False

    def execute(
        self,
        cmd: list[str],
        worktree_dir: Path,
        timeout_seconds: Optional[int] = None,
        limits_override: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, str, str, int]:
        if not self.is_available():
            raise SandboxUnavailableError(
                "HostedContainerSandbox is disabled or unconfigured in this environment. Fail-closed policy enforced."
            )

        cmd_run = list(cmd)
        binary = cmd_run[0]
        # Resolve full path if available
        resolved = shutil.which(binary)
        if not resolved:
            # Check backend/.bin and ~/.local/bin directly
            candidates = [
                Path(__file__).resolve().parent.parent.parent / ".bin" / binary,
                Path.home() / ".local" / "bin" / binary,
                Path("/usr/local/bin") / binary,
                Path("/usr/bin") / binary,
            ]
            for cand in candidates:
                if cand.is_file() and os.access(cand, os.X_OK):
                    resolved = str(cand)
                    break
        if resolved:
            cmd_run[0] = resolved

        timeout = timeout_seconds or limits.SCANNER_TOOL_TIMEOUT_SECONDS
        start_time = time.time()

        logger.info("Executing scanner '%s' inside hosted PaaS container sandbox (timeout: %ss)", binary, timeout)

        try:
            proc = subprocess.run(
                cmd_run,
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
            return -2, "", f"Hosted container process execution failed: {str(exc)}", duration_ms
