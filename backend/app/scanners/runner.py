"""Sandboxed container execution runner (Architecture §5, NFR-03, ADR-002)."""
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Tuple, Optional

from app.core.limits import limits
from app.core.errors import SecureScanException, ErrorCode
from app.sandbox import get_sandbox_engine, SandboxUnavailableError

# ANSI terminal escape sequence cleaner
ANSI_ESCAPE_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_terminal_escapes(text: str) -> str:
    """Sanitize scanner output by stripping terminal color/control sequences."""
    if not text:
        return ""
    return ANSI_ESCAPE_REGEX.sub("", text)


def build_sandbox_docker_cmd(
    image: str,
    worktree_dir: Path,
    command_args: list[str],
    memory_limit: str = "1g",
    cpu_limit: float = 1.5,
    pids_limit: int = 100
) -> list[str]:
    """
    Construct safe, isolated Docker CLI command enforcing Architecture §5 sandbox:
    - --network=none (Zero network egress)
    - --cap-drop=ALL
    - --security-opt=no-new-privileges:true
    - --user=1000:1000 (Non-root)
    - --read-only volume mount for repository code
    - --tmpfs for scratch output
    """
    worktree_abs = str(worktree_dir.resolve())

    cmd = [
        "docker", "run", "--rm",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user=1000:1000",
        "-v", f"{worktree_abs}:/repo:ro",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=100m",
        "-w", "/repo",
        f"--memory={memory_limit}",
        f"--cpus={cpu_limit}",
        f"--pids-limit={pids_limit}",
        image
    ]
    cmd.extend(command_args)
    return cmd


def execute_sandboxed_command(
    cmd: list[str],
    worktree_dir: Path,
    timeout_seconds: int | None = None
) -> Tuple[int, str, str, int]:
    """
    Execute scanner command through active sandbox engine (Docker, Bubblewrap, or SubprocessDev).
    Enforces timeout, resource constraints, terminal escape stripping, and production fail-closed.
    Returns (returncode, stdout, stderr, duration_ms).
    """
    engine = get_sandbox_engine()
    return engine.execute(cmd, worktree_dir, timeout_seconds=timeout_seconds)
