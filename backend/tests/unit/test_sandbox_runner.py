"""Unit tests for sandbox command construction and terminal output sanitization."""
from pathlib import Path
from app.scanners.runner import build_sandbox_docker_cmd, strip_terminal_escapes


def test_sandbox_docker_command_flags(tmp_path: Path):
    """Architecture §5: Docker command construction must enforce zero network and drop all caps."""
    cmd = build_sandbox_docker_cmd(
        image="semgrep/semgrep:1.102.0",
        worktree_dir=tmp_path,
        command_args=["semgrep", "scan", "--json"],
        memory_limit="1g",
        cpu_limit=1.5,
        pids_limit=100
    )

    cmd_str = " ".join(cmd)
    assert "--network=none" in cmd_str
    assert "--cap-drop=ALL" in cmd_str
    assert "--security-opt=no-new-privileges:true" in cmd_str
    assert "--user=1000:1000" in cmd_str
    assert ":/repo:ro" in cmd_str
    assert "--tmpfs /tmp:rw,noexec,nosuid,size=100m" in cmd_str
    assert "--memory=1g" in cmd_str
    assert "--cpus=1.5" in cmd_str
    assert "--pids-limit=100" in cmd_str
    assert "semgrep/semgrep:1.102.0" in cmd_str


def test_strip_terminal_escapes():
    colored_text = "\x1B[31m[ERROR]\x1B[0m \x1B[1mSecurity finding in file.py\x1B[0m"
    clean_text = strip_terminal_escapes(colored_text)
    assert clean_text == "[ERROR] Security finding in file.py"
    assert "\x1B" not in clean_text

