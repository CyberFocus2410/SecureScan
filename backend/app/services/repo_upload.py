"""Safe, bounded local repository archive (.zip) and folder upload service."""
import hashlib
import os
import re
import shutil
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Dict, Any, List, Tuple

from app.core.limits import limits
from app.core.errors import RepoTooLargeError, SecureScanException, ErrorCode
from app.services.github_import import (
    MEDIA_ASSET_EXTENSIONS,
    sanitize_and_enforce_caps,
    detect_languages_and_frameworks,
)

IGNORED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".next",
    ".nuxt",
    "__macosx",
}


def sanitize_project_name(raw_name: str | None) -> str:
    """Normalize an uploaded archive/folder name into a safe repository identifier."""
    if not raw_name:
        return "uploaded-repo"
    base = raw_name.strip()
    if base.lower().endswith(".zip"):
        base = base[:-4]
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", base).strip("-.")
    return (cleaned or "uploaded-repo")[:100]


def sanitize_relative_path(raw_path: str) -> Path | None:
    """
    Validate and normalize a relative file path from an upload or zip archive.
    Returns None if the path should be skipped (ignored directory, macOS metadata).
    Raises SecureScanException on path traversal attempts.
    """
    if not raw_path or "\x00" in raw_path:
        raise SecureScanException(
            code=ErrorCode.ERR_VALIDATION_ERROR,
            message="Uploaded archive contains an invalid or null-byte file path.",
        )

    normalized = raw_path.replace("\\", "/").lstrip("/")
    if not normalized or normalized.endswith("/"):
        return None

    # Reject Windows drive letters or absolute/traversal components
    if re.match(r"^[a-zA-Z]:", normalized):
        raise SecureScanException(
            code=ErrorCode.ERR_VALIDATION_ERROR,
            message=f"Absolute drive path rejected in upload: '{raw_path}'.",
        )

    posix = PurePosixPath(normalized)
    parts = posix.parts
    if not parts or any(p in ("..", "") for p in parts):
        raise SecureScanException(
            code=ErrorCode.ERR_VALIDATION_ERROR,
            message=f"Path traversal component rejected in upload: '{raw_path}'.",
        )

    # Skip ignored build/VCS/dependency directories
    if any(p.lower() in IGNORED_DIRS for p in parts[:-1]) or parts[-1].lower() in (".ds_store", "thumbs.db"):
        return None

    return Path(*parts)


def _unwrap_single_root_dir(target_dir: Path) -> None:
    """
    If an uploaded zip/folder wraps the entire project in a single top-level directory
    (e.g. `my-app-main/package.json`), move its contents up to `target_dir`.
    """
    entries = list(target_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        wrapper = entries[0]
        for child in list(wrapper.iterdir()):
            dest = target_dir / child.name
            if dest.exists():
                continue
            shutil.move(str(child), str(dest))
        try:
            wrapper.rmdir()
        except OSError:
            pass


def _compute_content_sha(target_dir: Path) -> str:
    """Compute a deterministic 40-character SHA-256 digest of the staged worktree."""
    hasher = hashlib.sha256()
    file_paths: List[Path] = []
    for root, _, files in os.walk(target_dir, followlinks=False):
        for f in files:
            file_paths.append(Path(root) / f)

    file_paths.sort(key=lambda p: p.relative_to(target_dir).as_posix())
    for fp in file_paths:
        rel = fp.relative_to(target_dir).as_posix()
        hasher.update(rel.encode("utf-8", errors="ignore"))
        try:
            with open(fp, "rb") as fh:
                while chunk := fh.read(65536):
                    hasher.update(chunk)
        except OSError:
            continue
    return hasher.hexdigest()[:40]


def extract_zip_safely(zip_stream: BinaryIO, target_dir: Path) -> Dict[str, Any]:
    """
    Safely extract a .zip archive into `target_dir` with Zip-Slip, symlink,
    Zip-Bomb, file-count, and size-cap protections.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    root_resolved = target_dir.resolve()

    try:
        zf = zipfile.ZipFile(zip_stream)
    except zipfile.BadZipFile:
        raise SecureScanException(
            code=ErrorCode.ERR_VALIDATION_ERROR,
            message="Uploaded file is not a valid .zip archive.",
        )

    total_files = 0
    total_bytes = 0

    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue

            # Reject symlinks inside zip archives (Unix mode 0o120000)
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                continue

            rel_path = sanitize_relative_path(info.filename)
            if rel_path is None:
                continue

            total_files += 1
            if total_files > limits.MAX_FILE_COUNT:
                raise RepoTooLargeError(
                    f"Uploaded repository exceeds file count limit ({limits.MAX_FILE_COUNT} files)."
                )

            is_media = rel_path.suffix.lower() in MEDIA_ASSET_EXTENSIONS
            max_single = limits.MAX_MEDIA_FILE_BYTES if is_media else limits.MAX_SINGLE_FILE_BYTES

            # Pre-check declared uncompressed size
            if info.file_size > max_single:
                if is_media:
                    continue
                raise RepoTooLargeError(
                    f"File '{rel_path.name}' exceeds maximum single file size ({max_single} bytes)."
                )

            if is_media and info.file_size > limits.MAX_SINGLE_FILE_BYTES:
                # Prune oversized non-code binary/media asset before extraction
                continue

            dest_path = (target_dir / rel_path).resolve()
            if not dest_path.is_relative_to(root_resolved):
                raise SecureScanException(
                    code=ErrorCode.ERR_VALIDATION_ERROR,
                    message=f"Zip-slip path escape detected: '{info.filename}'.",
                )

            dest_path.parent.mkdir(parents=True, exist_ok=True)

            # Stream-copy with real byte counting to defeat forged ZipInfo headers (Zip Bomb)
            written = 0
            with zf.open(info, "r") as src, open(dest_path, "wb") as dst:
                while chunk := src.read(65536):
                    written += len(chunk)
                    total_bytes += len(chunk)
                    if written > limits.MAX_SINGLE_FILE_BYTES:
                        if is_media:
                            break
                        raise RepoTooLargeError(
                            f"File '{rel_path.name}' exceeds maximum single file size ({limits.MAX_SINGLE_FILE_BYTES} bytes)."
                        )
                    if total_bytes > limits.MAX_REPO_SIZE_BYTES:
                        raise RepoTooLargeError(
                            f"Uploaded repository exceeds total size limit ({limits.MAX_REPO_SIZE_BYTES} bytes)."
                        )
                    dst.write(chunk)

            if is_media and written > limits.MAX_SINGLE_FILE_BYTES:
                dest_path.unlink(missing_ok=True)
                total_bytes -= written

    if total_files == 0:
        raise SecureScanException(
            code=ErrorCode.ERR_VALIDATION_ERROR,
            message="Uploaded archive contains no scannable source files.",
        )

    _unwrap_single_root_dir(target_dir)
    stats = sanitize_and_enforce_caps(target_dir)
    languages, frameworks = detect_languages_and_frameworks(target_dir)
    content_sha = _compute_content_sha(target_dir)

    return {
        "file_count": stats["file_count"],
        "total_bytes": stats["total_bytes"],
        "languages": languages,
        "frameworks": frameworks,
        "content_sha": content_sha,
    }


def save_uploaded_files(
    file_entries: List[Tuple[str, bytes]],
    target_dir: Path,
) -> Dict[str, Any]:
    """
    Safely write multi-file / local folder uploads into `target_dir` with
    path traversal, file-count, and size-cap enforcement.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    root_resolved = target_dir.resolve()

    total_files = 0
    total_bytes = 0

    for raw_rel_path, content in file_entries:
        rel_path = sanitize_relative_path(raw_rel_path)
        if rel_path is None:
            continue

        total_files += 1
        if total_files > limits.MAX_FILE_COUNT:
            raise RepoTooLargeError(
                f"Uploaded folder exceeds file count limit ({limits.MAX_FILE_COUNT} files)."
            )

        size = len(content)
        is_media = rel_path.suffix.lower() in MEDIA_ASSET_EXTENSIONS
        max_single = limits.MAX_MEDIA_FILE_BYTES if is_media else limits.MAX_SINGLE_FILE_BYTES

        if size > max_single:
            if is_media:
                continue
            raise RepoTooLargeError(
                f"File '{rel_path.name}' exceeds maximum single file size ({max_single} bytes)."
            )

        if is_media and size > limits.MAX_SINGLE_FILE_BYTES:
            continue

        total_bytes += size
        if total_bytes > limits.MAX_REPO_SIZE_BYTES:
            raise RepoTooLargeError(
                f"Uploaded folder exceeds total size limit ({limits.MAX_REPO_SIZE_BYTES} bytes)."
            )

        dest_path = (target_dir / rel_path).resolve()
        if not dest_path.is_relative_to(root_resolved):
            raise SecureScanException(
                code=ErrorCode.ERR_VALIDATION_ERROR,
                message=f"Path escape rejected: '{raw_rel_path}'.",
            )

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(content)

    if total_files == 0:
        raise SecureScanException(
            code=ErrorCode.ERR_VALIDATION_ERROR,
            message="Uploaded folder contains no scannable source files.",
        )

    _unwrap_single_root_dir(target_dir)
    stats = sanitize_and_enforce_caps(target_dir)
    languages, frameworks = detect_languages_and_frameworks(target_dir)
    content_sha = _compute_content_sha(target_dir)

    return {
        "file_count": stats["file_count"],
        "total_bytes": stats["total_bytes"],
        "languages": languages,
        "frameworks": frameworks,
        "content_sha": content_sha,
    }
