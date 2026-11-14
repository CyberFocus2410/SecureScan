"""Helper to dynamically generate and clean oversized test repos without committing huge blobs."""
import shutil
from pathlib import Path

def generate_file_count_bomb(target_dir: Path, count: int = 2005) -> None:
    """Generate directory with > 2000 tiny files to test file count cap."""
    target_dir.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (target_dir / f"file_{i}.txt").write_text("x", encoding="utf-8")

def generate_giant_file_bomb(target_dir: Path, size_mb: int = 6) -> None:
    """Generate a single file > 5MB to test single-file cap."""
    target_dir.mkdir(parents=True, exist_ok=True)
    big_file = target_dir / "giant_binary.bin"
    chunk = b"A" * (1024 * 1024)  # 1MB
    with open(big_file, "wb") as f:
        for _ in range(size_mb):
            f.write(chunk)

def cleanup_oversized(target_dir: Path) -> None:
    """Clean up generated files."""
    if target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)

