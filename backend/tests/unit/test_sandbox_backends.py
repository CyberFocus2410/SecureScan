"""Unit tests for sandbox backend abstractions and fail-closed security (Architecture §5, ADR-002)."""
import pytest
from pathlib import Path
from app.core.config import settings
from app.sandbox.base import SandboxUnavailableError
from app.sandbox.docker import DockerSandbox
from app.sandbox.bubblewrap import BubblewrapSandbox
from app.sandbox.subprocess_dev import SubprocessDevSandbox
from app.sandbox import get_sandbox_engine


def test_docker_sandbox_command_flags():
    """Verify DockerSandbox constructs mandatory Architecture §5 isolation flags."""
    docker = DockerSandbox(default_image="securescan-static-worker:latest")
    worktree = Path("/tmp/test_worktree")
    cmd = docker.build_container_cmd(["semgrep", "scan"], worktree)

    cmd_str = " ".join(cmd)
    assert "--network=none" in cmd_str
    assert "--cap-drop=ALL" in cmd_str
    assert "--security-opt=no-new-privileges:true" in cmd_str
    assert "--user=1000:1000" in cmd_str
    assert ":/repo:ro" in cmd_str
    assert "--tmpfs /tmp:rw,noexec,nosuid,size=100m" in cmd_str
    assert "-w /repo" in cmd_str
    assert "securescan-static-worker:latest" in cmd_str
    assert "semgrep scan" in cmd_str


def test_bubblewrap_sandbox_command_flags():
    """Verify BubblewrapSandbox constructs mandatory user-namespace isolation flags."""
    bwrap = BubblewrapSandbox()
    worktree = Path("/tmp/test_worktree")
    cmd = bwrap.build_bwrap_cmd(["gitleaks", "detect"], worktree)

    cmd_str = " ".join(cmd)
    assert "--unshare-net" in cmd_str
    assert "--unshare-pid" in cmd_str
    assert "--unshare-ipc" in cmd_str
    assert "--unshare-uts" in cmd_str
    assert "--ro-bind" in cmd_str
    assert "/repo" in cmd_str
    assert "--tmpfs /tmp" in cmd_str
    assert "--chdir /repo" in cmd_str
    assert "gitleaks detect" in cmd_str


def test_subprocess_dev_sandbox_in_development():
    """Verify SubprocessDevSandbox executes benign commands in development/testing."""
    orig_env = settings.ENVIRONMENT
    try:
        settings.ENVIRONMENT = "development"
        engine = SubprocessDevSandbox()
        code, stdout, stderr, dur = engine.execute(
            ["python", "-c", "print('hello dev sandbox')"],
            Path.cwd()
        )
        assert code == 0
        assert "hello dev sandbox" in stdout
    finally:
        settings.ENVIRONMENT = orig_env


def test_subprocess_dev_fail_closed_in_production():
    """CRITICAL SECURITY TEST: SubprocessDevSandbox MUST fail closed in production."""
    orig_env = settings.ENVIRONMENT
    try:
        settings.ENVIRONMENT = "production"
        engine = SubprocessDevSandbox()
        with pytest.raises(SandboxUnavailableError) as exc_info:
            engine.execute(["python", "-c", "print('should not run')"], Path.cwd())
        assert "Fail-closed policy enforced" in str(exc_info.value)
    finally:
        settings.ENVIRONMENT = orig_env


def test_get_sandbox_engine_production_fail_closed(monkeypatch):
    """Verify get_sandbox_engine rejects unisolated fallback in production."""
    orig_env = settings.ENVIRONMENT
    try:
        settings.ENVIRONMENT = "production"
        # Simulate host lacking both Docker and Bubblewrap
        monkeypatch.setattr(DockerSandbox, "is_available", lambda self: False)
        monkeypatch.setattr(BubblewrapSandbox, "is_available", lambda self: False)

        with pytest.raises(SandboxUnavailableError) as exc_info:
            get_sandbox_engine("auto")
        assert "Fail-closed policy enforced" in str(exc_info.value)
    finally:
        settings.ENVIRONMENT = orig_env
