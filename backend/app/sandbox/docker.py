"""Docker/Podman rootless container sandbox implementation (Architecture §5, ADR-002)."""
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


class DockerSandbox(SandboxEngine):
    """
    Isolated container execution backend.
    Enforces Architecture §5 sandbox constraints:
    - --network=none (Zero network egress)
    - --cap-drop=ALL
    - --security-opt=no-new-privileges:true
    - --user=1000:1000 (Non-root)
    - --read-only volume mount for repository code
    - --tmpfs for scratch output
    """

    def __init__(self, default_image: str = "securescan-static-worker:latest"):
        self.default_image = default_image
        self._binary = shutil.which("docker") or shutil.which("podman")

    @property
    def name(self) -> str:
        return "docker"

    def is_available(self) -> bool:
        if not self._binary:
            return False
        try:
            res = subprocess.run(
                [self._binary, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3
            )
            return res.returncode == 0
        except Exception:
            return False

    def build_container_cmd(
        self,
        command_args: list[str],
        worktree_dir: Path,
        image: Optional[str] = None,
        limits_override: Optional[Dict[str, Any]] = None
    ) -> list[str]:
        target_image = image or self.default_image
        overrides = limits_override or {}
        memory = overrides.get("memory", "1g")
        cpus = overrides.get("cpus", 1.5)
        pids = overrides.get("pids", 100)
        network = overrides.get("network", "none")

        worktree_abs = str(worktree_dir.resolve())
        cmd = [
            self._binary or "docker",
            "run", "--rm",
            f"--network={network}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--user=1000:1000",
            "-v", f"{worktree_abs}:/repo:ro",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=100m",
            "-w", "/repo",
            f"--memory={memory}",
            f"--cpus={cpus}",
            f"--pids-limit={pids}",
            target_image
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
        container_cmd = self.build_container_cmd(cmd, worktree_dir, limits_override=limits_override)
        start_time = time.time()

        try:
            proc = subprocess.run(
                container_cmd,
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
            return -1, "", f"Docker execution timed out after {timeout} seconds", duration_ms
        except Exception as exc:
            duration_ms = int((time.time() - start_time) * 1000)
            return -2, "", f"Docker execution failed: {str(exc)}", duration_ms
