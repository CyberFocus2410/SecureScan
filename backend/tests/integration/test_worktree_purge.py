"""Worktree purge verification test (NFR-12, FR-IMP-03)."""
import uuid
from pathlib import Path
from app.core.config import settings
from app.services.github_import import purge_worktree


def test_worktree_purge_removes_directory():
    """Verify purge_worktree cleans up target directory completely."""
    test_id = str(uuid.uuid4())
    worktree_dir = settings.WORKTREE_STORAGE_DIR / test_id
    worktree_dir.mkdir(parents=True, exist_ok=True)

    # Populate temporary files
    (worktree_dir / "temp_source.py").write_text("code = 1", encoding="utf-8")
    (worktree_dir / "temp_manifest.json").write_text("{}", encoding="utf-8")
    assert worktree_dir.exists()

    # Purge
    purge_worktree(worktree_dir)

    # Assert directory is eliminated
    assert not worktree_dir.exists()

