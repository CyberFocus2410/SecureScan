"""Bubblewrap/nsjail Linux user-namespace sandbox implementation (Architecture §5, ADR-002)."""
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

from app.core.limits import limits
from app.sandbox.base import SandboxEngine

ANSI_ESCAPE_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_terminal_escapes(text: str) -> str:
    """Sanitize scanner output by stripping terminal color/control sequences."""
    if not text:
        return ""
    return ANSI_ESCAPE_REGEX.sub("", text)


class BubblewrapSandbox(SandboxEngine):
    """
    Linux user-namespace isolation using bubblewrap (`bwrap`) or `nsjail`.
    Used for non-Docker hosts (Render, VPS).
    Enforces:
    - --unshare-net (Zero network egress)
    - --unshare-pid, --unshare-ipc, --unshare-uts
    - Read-only bind mount for host root and repo
    - Tmpfs for /tmp
    """

    def __init__(self):
        self._bwrap = shutil.which("bwrap")
        self._nsjail = shutil.which("nsjail")

    @property
    def name(self) -> str:
        return "bubblewrap"

    def is_available(self) -> bool:
        if self._bwrap:
            try:
                res = subprocess.run([self._bwrap, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                return res.returncode == 0
            except Exception:
                pass
        if self._nsjail:
            try:
                res = subprocess.run([self._nsjail, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                return res.returncode == 0
            except Exception:
                pass
        return False

    def build_bwrap_cmd(self, command_args: list[str], worktree_dir: Path) -> list[str]:
        worktree_abs = str(worktree_dir.resolve())
        cmd = [
            self._bwrap or "bwrap",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--ro-bind", "/", "/",
            "--ro-bind", worktree_abs, "/repo",
            "--tmpfs", "/tmp",
            "--proc", "/proc",
            "--dev", "/dev",
            "--chdir", "/repo"
        ]
        cmd.extend(command_args)
        return cmd

    def execute(
        self,
        cmd: list[str],
        worktree_dir: Path,
        timeout_seconds: Optional[int] = None,
        limits_override: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, str, str, int]:
        timeout = timeout_seconds or limits.SCANNER_TOOL_TIMEOUT_SECONDS
        start_time = time.time()
        bwrap_cmd = self.build_bwrap_cmd(cmd, worktree_dir)

        try:
            proc = subprocess.run(
                bwrap_cmd,
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
            return -1, "", f"Bubblewrap execution timed out after {timeout} seconds", duration_ms
        except Exception as exc:
            duration_ms = int((time.time() - start_time) * 1000)
            return -2, "", f"Bubblewrap execution failed: {str(exc)}", duration_ms
