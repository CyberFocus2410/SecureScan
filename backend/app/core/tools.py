"""Centralized CLI security scanner tool resolver, downloader, and verification engine."""
import io
import logging
import os
import platform
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
BIN_DIR = BACKEND_DIR / ".bin"
LOCAL_BIN_DIR = Path.home() / ".local" / "bin"

# Standalone binary definitions (Linux x86_64)
LINUX_BINARIES: Dict[str, Dict[str, Any]] = {
    "gitleaks": {
        "url": "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz",
        "type": "tar.gz",
        "bin_name": "gitleaks",
        "test_arg": "version",
    },
    "trufflehog": {
        "url": "https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.3/trufflehog_3.88.3_linux_amd64.tar.gz",
        "type": "tar.gz",
        "bin_name": "trufflehog",
        "test_arg": "--version",
    },
    "osv-scanner": {
        "url": "https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_linux_amd64",
        "type": "direct",
        "bin_name": "osv-scanner",
        "test_arg": "--version",
    },
    "syft": {
        "url": "https://github.com/anchore/syft/releases/download/v1.19.0/syft_1.19.0_linux_amd64.tar.gz",
        "type": "tar.gz",
        "bin_name": "syft",
        "test_arg": "version",
    },
    "hadolint": {
        "url": "https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64",
        "type": "direct",
        "bin_name": "hadolint",
        "test_arg": "--version",
    },
    "actionlint": {
        "url": "https://github.com/rhysd/actionlint/releases/download/v1.7.4/actionlint_1.7.4_linux_amd64.tar.gz",
        "type": "tar.gz",
        "bin_name": "actionlint",
        "test_arg": "--version",
    },
    "zizmor": {
        "url": "https://github.com/woodruffw/zizmor/releases/download/v1.1.1/zizmor-x86_64-unknown-linux-musl.tar.gz",
        "type": "tar.gz",
        "bin_name": "zizmor",
        "test_arg": "--version",
    },
    "trivy": {
        "url": "https://github.com/aquasecurity/trivy/releases/download/v0.58.0/trivy_0.58.0_Linux-64bit.tar.gz",
        "type": "tar.gz",
        "bin_name": "trivy",
        "test_arg": "--version",
    },
}


def find_cli_tool(binary_name: str) -> Optional[str]:
    """
    Find full executable path for a CLI tool across standard PATH, .bin, and local user directories.
    Handles Windows (.exe) and POSIX binary extensions.
    """
    # 1. Standard shutil.which lookup
    found = shutil.which(binary_name)
    if found:
        return found

    # 2. Candidate directory inspection
    names_to_try = [binary_name]
    if sys.platform == "win32" and not binary_name.endswith(".exe"):
        names_to_try.append(f"{binary_name}.exe")

    candidates = [
        BIN_DIR,
        LOCAL_BIN_DIR,
        Path(sys.prefix) / "bin",
        Path(sys.prefix) / "Scripts",
        Path("/usr/local/bin"),
        Path("/usr/bin"),
        Path("/bin"),
    ]

    for candidate_dir in candidates:
        for name in names_to_try:
            target = candidate_dir / name
            if target.is_file() and (sys.platform == "win32" or os.access(target, os.X_OK)):
                return str(target)

    return None


def check_cli_tool(binary_name: str, version_arg: str = "--version") -> Tuple[bool, Optional[str]]:
    """
    Check whether a binary is available and executable, returning (is_available, version_line).
    Safe, fast, and non-blocking with 3s timeout.
    """
    path = find_cli_tool(binary_name)
    if not path:
        return False, None

    try:
        proc = subprocess.run(
            [path, version_arg],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        output = (proc.stdout or proc.stderr or "").strip()
        version_line = output.splitlines()[0] if output else "installed"
        return True, version_line[:60]
    except Exception as exc:
        logger.debug("Executing %s %s failed: %s", path, version_arg, exc)
        return True, "installed"


def ensure_tools_installed(force: bool = False) -> None:
    """
    Self-healing bootstrap for Render/Linux deployment.
    Downloads and extracts missing standalone Linux x86_64 binaries directly into backend/.bin/.
    """
    # Standalone binaries are Linux x86_64 distributions
    if not (sys.platform.startswith("linux") or os.environ.get("RENDER") == "true"):
        return

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    LOCAL_BIN_DIR.mkdir(parents=True, exist_ok=True)

    has_curl = shutil.which("curl") is not None
    has_tar = shutil.which("tar") is not None

    for name, spec in LINUX_BINARIES.items():
        bin_path = BIN_DIR / spec["bin_name"]
        local_bin_path = LOCAL_BIN_DIR / spec["bin_name"]

        if not force and bin_path.is_file() and os.access(bin_path, os.X_OK):
            # Already installed and executable
            if not local_bin_path.exists():
                try:
                    shutil.copy2(bin_path, local_bin_path)
                    os.chmod(local_bin_path, 0o755)
                except Exception:
                    pass
            continue

        logger.info("Bootstrap: Downloading primary tool '%s' from %s...", name, spec["url"])

        download_success = False

        # Attempt 1: Fast native curl download
        if has_curl:
            try:
                if spec["type"] == "direct":
                    curl_cmd = ["curl", "-sSL", "--connect-timeout", "10", "--max-time", "30", "-o", str(bin_path), spec["url"]]
                    res = subprocess.run(curl_cmd, capture_output=True, timeout=35)
                    if res.returncode == 0 and bin_path.is_file() and bin_path.stat().st_size > 1000:
                        os.chmod(bin_path, 0o755)
                        download_success = True
                elif spec["type"] == "tar.gz" and has_tar:
                    tmp_archive = BIN_DIR / f"{name}_temp.tar.gz"
                    curl_cmd = ["curl", "-sSL", "--connect-timeout", "10", "--max-time", "30", "-o", str(tmp_archive), spec["url"]]
                    res = subprocess.run(curl_cmd, capture_output=True, timeout=35)
                    if res.returncode == 0 and tmp_archive.is_file():
                        tar_cmd = ["tar", "-xzf", str(tmp_archive), "-C", str(BIN_DIR), spec["bin_name"]]
                        t_res = subprocess.run(tar_cmd, capture_output=True, timeout=15)
                        if t_res.returncode == 0 and bin_path.is_file():
                            os.chmod(bin_path, 0o755)
                            download_success = True
                    if tmp_archive.exists():
                        tmp_archive.unlink()
            except Exception as exc:
                logger.warning("Bootstrap: curl download failed for %s: %s", name, exc)

        # Attempt 2: Python urllib fallback
        if not download_success:
            try:
                import urllib.request
                req = urllib.request.Request(spec["url"], headers={"User-Agent": "SecureScan/2.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = resp.read()

                if spec["type"] == "direct":
                    with open(bin_path, "wb") as f:
                        f.write(data)
                    os.chmod(bin_path, 0o755)
                    download_success = True
                elif spec["type"] == "tar.gz":
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                        bin_name = spec["bin_name"]
                        for member in tar.getmembers():
                            if member.name == bin_name or member.name.endswith("/" + bin_name):
                                f_obj = tar.extractfile(member)
                                if f_obj:
                                    with open(bin_path, "wb") as f_out:
                                        f_out.write(f_obj.read())
                                    os.chmod(bin_path, 0o755)
                                    download_success = True
                                    break
            except Exception as exc:
                logger.warning("Bootstrap: Python download failed for %s: %s", name, exc)

        if download_success:
            logger.info("Bootstrap: Successfully installed %s (%d bytes)", name, bin_path.stat().st_size)
            try:
                shutil.copy2(bin_path, local_bin_path)
                os.chmod(local_bin_path, 0o755)
            except Exception:
                pass
        else:
            logger.warning("Bootstrap: Could not download %s; fallback chains will remain active.", name)
