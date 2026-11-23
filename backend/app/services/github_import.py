"""Safe, bounded GitHub repository ingestion service."""
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from typing import Tuple, List, Dict, Any

from app.core.limits import limits
from app.core.safe_fetch import is_safe_url
from app.core.errors import (
    InvalidRepoUrlError,
    RepoTooLargeError,
    SecureScanException,
    ErrorCode
)

# Strict GitHub URL regex: https://github.com/{owner}/{repo} (optional .git, optional trailing slash)
GITHUB_URL_REGEX = re.compile(
    r"^https://github\.com/(?P<owner>[a-zA-Z0-9_.-]+)/(?P<repo>[a-zA-Z0-9_.-]+?)(?:\.git)?/?$"
)

# Safe git branch name pattern
SAFE_BRANCH_REGEX = re.compile(
    r"^[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*$"
)

# Common media, font, image, ML model, and binary asset extensions exempt from code file caps
MEDIA_ASSET_EXTENSIONS = {
    # Video & Audio
    ".mp4", ".mov", ".avi", ".mkv", ".webm", ".flv", ".wmv",
    ".mp3", ".wav", ".ogg", ".flac", ".aac",
    # Images & Icons
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".tiff", ".bmp",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # AI / ML models & weights (ONNX, PyTorch, TF/Keras, Safetensors, etc.)
    ".onnx", ".pt", ".pth", ".h5", ".hdf5", ".tflite", ".safetensors",
    ".joblib", ".pkl", ".pickle", ".model", ".pb", ".weights", ".caffemodel",
    # Scientific data, arrays & datasets
    ".parquet", ".arrow", ".npy", ".npz", ".feather",
    # Documents & Compressed Archives
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z"
}


def parse_and_validate_github_url(raw_url: str) -> Tuple[str, str, str]:
    """
    Strict URL parser and validator (FR-IMP-01, NFR-02):
    - Accepts ONLY https://github.com/{owner}/{repo}
    - Strips .git
    - Rejects query parameters, fragments, userinfo, IP addresses, non-HTTPS protocols,
      and non-github hosts BEFORE any network call is initiated.
    Returns (owner, repo, canonical_url).
    """
    if not raw_url or not isinstance(raw_url, str):
        raise InvalidRepoUrlError("Repository URL must be a non-empty string.")

    raw_url = raw_url.strip()

    try:
        parsed = urlparse(raw_url)
    except Exception as exc:
        raise InvalidRepoUrlError(f"Malformed URL: {exc}")

    # Protocol must be https
    if parsed.scheme.lower() != "https":
        raise InvalidRepoUrlError(f"Unsupported protocol '{parsed.scheme}'. Only HTTPS is permitted.")

    # Host must be strictly 'github.com'
    if parsed.netloc.lower() != "github.com":
        raise InvalidRepoUrlError(f"Unsupported host '{parsed.netloc}'. Only 'github.com' is permitted.")

    # Reusable SSRF guard verification (Playbook §7)
    safe, reason = is_safe_url(raw_url, allowed_schemes=("https",), allowed_hosts=("github.com",), block_private_ips=False)
    if not safe:
        raise InvalidRepoUrlError(reason)

    # Rejects userinfo (e.g. user:pass@github.com)
    if parsed.username or parsed.password:
        raise InvalidRepoUrlError("Userinfo/credentials embedded in URL are strictly prohibited.")

    # Rejects query strings and fragments
    if parsed.query:
        raise InvalidRepoUrlError("Query parameters are not permitted in repository URLs.")
    if parsed.fragment:
        raise InvalidRepoUrlError("URL fragments are not permitted in repository URLs.")

    # Rejects IP addresses or port numbers in host
    if ":" in parsed.netloc or re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.netloc):
        raise InvalidRepoUrlError("IP addresses and port specifications are prohibited.")

    # Regex match on path components
    match = GITHUB_URL_REGEX.match(raw_url)
    if not match:
        raise InvalidRepoUrlError("URL must match format: https://github.com/{owner}/{repo}")

    owner = match.group("owner")
    repo = match.group("repo")

    # Guard against traversal / reserved tokens
    if owner in (".", "..") or repo in (".", ".."):
        raise InvalidRepoUrlError("Invalid repository owner or name.")

    canonical_url = f"https://github.com/{owner}/{repo}"
    return owner, repo, canonical_url


def validate_branch(branch: str) -> str:
    """Validate git branch reference characters."""
    if not branch or not isinstance(branch, str):
        return "main"
    branch = branch.strip()
    if not SAFE_BRANCH_REGEX.match(branch) or ".." in branch or "@{" in branch or branch.startswith("/"):
        raise InvalidRepoUrlError(f"Invalid or unsafe branch reference '{branch}'.")
    return branch


def resolve_commit_sha(canonical_url: str, branch: str = "main") -> str:
    """
    Query GitHub remote to resolve branch into an exact 40-character commit SHA (FR-IMP-02).
    Uses git ls-remote with strict timeout.
    """
    cmd = [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "ls-remote",
        "--heads",
        canonical_url,
        branch
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=limits.CLONE_TIMEOUT_SECONDS
        )
        if proc.returncode != 0:
            raise SecureScanException(
                code=ErrorCode.ERR_REPO_NOT_FOUND,
                message=f"Repository or branch '{branch}' could not be resolved on GitHub.",
                details={"git_stderr": proc.stderr.strip()}
            )
        output = proc.stdout.strip()
        if not output:
            # Fallback: check if branch might be main/master or HEAD
            raise SecureScanException(
                code=ErrorCode.ERR_INVALID_BRANCH,
                message=f"Branch '{branch}' was not found in remote repository."
            )
        # ls-remote output format: <sha>\trefs/heads/<branch>
        sha = output.split()[0]
        if not re.match(r"^[0-9a-fA-F]{40}$", sha):
            raise SecureScanException(
                code=ErrorCode.ERR_REPO_NOT_FOUND,
                message="Failed to parse 40-character commit SHA from remote."
            )
        return sha.lower()
    except subprocess.TimeoutExpired:
        raise SecureScanException(
            code=ErrorCode.ERR_CLONE_TIMEOUT,
            message=f"Resolving branch timed out after {limits.CLONE_TIMEOUT_SECONDS}s."
        )


def clone_shallow_worktree(
    canonical_url: str,
    target_dir: Path,
    branch: str = "main",
    commit_sha: str | None = None
) -> str:
    """
    Perform a bounded shallow fetch into target_dir (FR-IMP-02, FR-IMP-03, NFR-01):
    - --depth=1
    - --no-recurse-submodules
    - -c core.hooksPath=/dev/null (No git hooks executed)
    - LFS filter disabled
    Returns the resolved commit SHA.
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "-c", "filter.lfs.smudge=",
        "-c", "filter.lfs.required=false",
        "clone",
        "--depth=1",
        "--branch", branch,
        "--no-recurse-submodules",
        canonical_url,
        str(target_dir)
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=limits.CLONE_TIMEOUT_SECONDS
        )
        if proc.returncode != 0:
            raise SecureScanException(
                code=ErrorCode.ERR_REPO_NOT_FOUND,
                message=f"Failed to clone repository from '{canonical_url}'.",
                details={"git_stderr": proc.stderr.strip()}
            )

        # Resolve local HEAD commit SHA
        rev_cmd = ["git", "-C", str(target_dir), "rev-parse", "HEAD"]
        rev_proc = subprocess.run(rev_cmd, stdout=subprocess.PIPE, text=True, check=True)
        resolved_sha = rev_proc.stdout.strip().lower()

        # Strip .git database to prevent internal packfiles/objects from consuming space
        git_dir = target_dir / ".git"
        if git_dir.exists():
            shutil.rmtree(git_dir, ignore_errors=True)

        # Sanitize and verify bounded constraints
        sanitize_and_enforce_caps(target_dir)

        return resolved_sha
    except subprocess.TimeoutExpired:
        purge_worktree(target_dir)
        raise SecureScanException(
            code=ErrorCode.ERR_CLONE_TIMEOUT,
            message=f"Git clone operation timed out after {limits.CLONE_TIMEOUT_SECONDS}s."
        )
    except Exception:
        purge_worktree(target_dir)
        raise


def sanitize_and_enforce_caps(worktree_dir: Path) -> Dict[str, Any]:
    """
    Sanitize worktree and enforce bounding caps (FR-IMP-03, FR-IMP-04, NFR-02):
    1. Removes any .git/hooks directory.
    2. Removes or neutralizes symlinks escaping the worktree root.
    3. Counts files and bytes; raises RepoTooLargeError if caps are exceeded.
    """
    hooks_dir = worktree_dir / ".git" / "hooks"
    if hooks_dir.exists():
        shutil.rmtree(hooks_dir, ignore_errors=True)

    total_files = 0
    total_bytes = 0
    root_resolved = worktree_dir.resolve()

    for root, dirs, files in os.walk(worktree_dir, followlinks=False):
        current_dir = Path(root)

        # Do not recurse into internal .git database directory (packfiles, objects)
        dirs[:] = [d for d in dirs if d.lower() != ".git"]
        if any(p.lower() == ".git" for p in current_dir.parts):
            continue

        # Inspect directories for symlinks
        for d in list(dirs):
            d_path = current_dir / d
            if d_path.is_symlink():
                target_resolved = d_path.resolve()
                if not str(target_resolved).startswith(str(root_resolved)):
                    # Symlink escapes worktree root! Remove immediately.
                    d_path.unlink()
                    dirs.remove(d)

        # Inspect files
        for f in files:
            f_path = current_dir / f
            total_files += 1

            if total_files > limits.MAX_FILE_COUNT:
                raise RepoTooLargeError(
                    f"Repository exceeds file count limit ({limits.MAX_FILE_COUNT} files)."
                )

            if f_path.is_symlink():
                target_resolved = f_path.resolve()
                if not str(target_resolved).startswith(str(root_resolved)):
                    # Malicious symlink escaping root
                    f_path.unlink()
                    continue

            try:
                f_size = f_path.stat().st_size
                is_media = f_path.suffix.lower() in MEDIA_ASSET_EXTENSIONS
                max_single = limits.MAX_MEDIA_FILE_BYTES if is_media else limits.MAX_SINGLE_FILE_BYTES

                if f_size > max_single:
                    if is_media:
                        # Non-code asset exceeds cap (e.g., massive video or oversized model weights).
                        # Safely prune from worktree so SAST scanning proceeds on code without OOM crash.
                        f_path.unlink()
                        continue
                    else:
                        # Single code/unclassified file exceeds cap (e.g. giant binary / bomb)
                        raise RepoTooLargeError(
                            f"File '{f}' exceeds maximum single file size ({max_single} bytes)."
                        )
                if is_media and f_size > limits.MAX_SINGLE_FILE_BYTES:
                    # Non-code asset (e.g. ML model weights like model.onnx, video, large datasets).
                    # Safely prune from worktree so SAST scanning proceeds on code without OOM crash.
                    f_path.unlink()
                    continue

                if f_size > limits.MAX_SINGLE_FILE_BYTES:
                    # Single code/unclassified file exceeds cap (e.g. giant binary / bomb)
                    raise RepoTooLargeError(
                        f"File '{f}' exceeds maximum single file size ({limits.MAX_SINGLE_FILE_BYTES} bytes)."
                    )
                total_bytes += f_size
            except (OSError, FileNotFoundError):
                continue

            if total_bytes > limits.MAX_REPO_SIZE_BYTES:
                raise RepoTooLargeError(
                    f"Repository exceeds total size limit ({limits.MAX_REPO_SIZE_BYTES} bytes)."
                )

    return {
        "file_count": total_files,
        "total_bytes": total_bytes
    }


def detect_languages_and_frameworks(worktree_dir: Path) -> Tuple[List[str], List[str]]:
    """
    Safe static discovery of languages and frameworks (FR-IMP-05).
    Targets: FastAPI, Flask, Django, Express, Next.js.
    """
    languages = set()
    frameworks = set()

    for root, _, files in os.walk(worktree_dir, followlinks=False):
        # Skip git directory
        if ".git" in root:
            continue

        for f in files:
            name_lower = f.lower()

            # Languages by extension
            if name_lower.endswith(".py"):
                languages.add("Python")
            elif name_lower.endswith((".js", ".jsx")):
                languages.add("JavaScript")
            elif name_lower.endswith((".ts", ".tsx")):
                languages.add("TypeScript")
            elif name_lower.endswith(".go"):
                languages.add("Go")
            elif name_lower.endswith(".java"):
                languages.add("Java")

            # Dependency & framework markers
            file_path = Path(root) / f

            # Python manifests & source
            if name_lower in ("requirements.txt", "pyproject.toml", "setup.py", "pipfile"):
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
                    if "fastapi" in content:
                        frameworks.add("FastAPI")
                    if "flask" in content:
                        frameworks.add("Flask")
                    if "django" in content:
                        frameworks.add("Django")
                except Exception:
                    pass

            # Node manifests
            if name_lower == "package.json":
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
                    if '"express"' in content:
                        frameworks.add("Express")
                    if '"next"' in content:
                        frameworks.add("Next.js")
                    if '"react"' in content:
                        frameworks.add("React")
                    if '"vue"' in content:
                        frameworks.add("Vue")
                    if '"@nestjs/' in content:
                        frameworks.add("NestJS")
                except Exception:
                    pass

    return sorted(list(languages)), sorted(list(frameworks))


def purge_worktree(worktree_dir: Path) -> None:
    """Purge temporary cloned repository worktree (NFR-12)."""
    if worktree_dir.exists():
        shutil.rmtree(worktree_dir, ignore_errors=True)

