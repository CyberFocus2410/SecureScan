"""Setup script to construct the malicious symlink and hook fixture."""
import os
import sys
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent

def setup_fixture():
    # 1. Create a normal file
    app_file = FIXTURE_DIR / "app.py"
    app_file.write_text("print('Safe app')", encoding="utf-8")

    # 2. Create hooks directory with a malicious hook script
    hooks_dir = FIXTURE_DIR / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_script = hooks_dir / "post-checkout"
    hook_script.write_text(
        "#!/bin/sh\necho 'PWNED' > " + str(FIXTURE_DIR / "hacked_marker.txt") + "\n",
        encoding="utf-8"
    )

    # 3. Create a malicious symlink pointing outside worktree root
    evil_link = FIXTURE_DIR / "escaped_link"
    if evil_link.exists() or evil_link.is_symlink():
        try:
            evil_link.unlink()
        except OSError:
            pass

    target = Path("..") / "outside.txt"
    try:
        os.symlink(str(target), str(evil_link))
        print("Created malicious symlink pointing to:", target)
    except OSError:
        # On Windows without developer mode/admin rights, symlink creation might fail
        # In that case, we create a placeholder simulating the link
        print("Symlink creation skipped or requires permissions.")

if __name__ == "__main__":
    setup_fixture()

