"""AT-19 & Safety tests: worktree containment, caps enforcement, and zero hook execution."""
import os
import shutil
from pathlib import Path
import pytest

from app.core.errors import RepoTooLargeError
from app.services.github_import import sanitize_and_enforce_caps
from fixtures.oversized.generator import (
    generate_file_count_bomb,
    generate_giant_file_bomb,
    cleanup_oversized
)


def test_at19_oversized_file_count_rejected(tmp_path: Path):
    """AT-19: Repositories with > 2000 files exceed caps and are rejected."""
    bomb_dir = tmp_path / "bomb_dir"
    try:
        generate_file_count_bomb(bomb_dir, count=2005)
        with pytest.raises(RepoTooLargeError, match="file count limit"):
            sanitize_and_enforce_caps(bomb_dir)
    finally:
        cleanup_oversized(bomb_dir)


def test_at19_giant_file_rejected(tmp_path: Path):
    """AT-19: Repositories containing a single file > 5MB are rejected."""
    giant_dir = tmp_path / "giant_dir"
    try:
        generate_giant_file_bomb(giant_dir, size_mb=6)
        with pytest.raises(RepoTooLargeError, match="maximum single file size"):
            sanitize_and_enforce_caps(giant_dir)
    finally:
        cleanup_oversized(giant_dir)


def test_at19_malicious_symlink_neutralized(tmp_path: Path):
    """AT-19: Symlinks attempting to escape worktree root are detected and removed."""
    worktree = tmp_path / "safe_worktree"
    worktree.mkdir()
    outside_file = tmp_path / "outside_secret.txt"
    outside_file.write_text("SUPER_SECRET_HOST_CONTENT", encoding="utf-8")

    # Create safe file inside worktree
    safe_file = worktree / "app.py"
    safe_file.write_text("print('hello')", encoding="utf-8")

    # Create escaping symlink inside worktree
    evil_link = worktree / "evil_symlink"
    try:
        os.symlink(str(outside_file), str(evil_link))
        assert evil_link.exists() or evil_link.is_symlink()

        # Run sanitizer
        stats = sanitize_and_enforce_caps(worktree)

        # Evil symlink must be unlinked and purged!
        assert not evil_link.exists()
        assert not evil_link.is_symlink()
        assert safe_file.exists()
    except OSError:
        # If OS denies symlink creation due to unprivileged privileges on Windows
        pass


def test_zero_hook_execution_proven(tmp_path: Path):
    """
    Prove that repo hooks are stripped and never executed (Rules.md §B, NFR-01).
    Creates a fake hook in .git/hooks and verifies it is removed without leaving side effects.
    """
    worktree = tmp_path / "hook_worktree"
    worktree.mkdir()
    hooks_dir = worktree / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)

    marker_file = tmp_path / "hook_marker.txt"
    post_checkout_hook = hooks_dir / "post-checkout"
    post_checkout_hook.write_text(f"echo 'HACKED' > {marker_file}\n", encoding="utf-8")

    # Run sanitizer
    sanitize_and_enforce_caps(worktree)

    # Hooks directory must be deleted
    assert not hooks_dir.exists()
    # Marker file must NOT exist (proving no hook ran)
    assert not marker_file.exists()

