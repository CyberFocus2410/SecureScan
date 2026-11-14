"""Sandboxed container execution runner (Architecture §5, NFR-03)."""
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Tuple

from app.core.limits import limits
from app.core.errors import SecureScanException, ErrorCode

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
    Execute scanner command with timeout and stripped terminal output.
    Returns (returncode, stdout, stderr, duration_ms).
    """
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
        stdout = strip_terminal_escapes(proc.stdout)
        stderr = strip_terminal_escapes(proc.stderr)
        return proc.returncode, stdout, stderr, duration_ms

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        return -1, "", f"Execution timed out after {timeout} seconds", duration_ms
    except Exception as exc:
        duration_ms = int((time.time() - start_time) * 1000)
        return -2, "", f"Process execution failed: {str(exc)}", duration_ms

