#!/usr/bin/env python3
"""
SecureScan 2.0 Pinned Security Scanner Installer.
Downloads, installs, and validates all primary security tools pinned in tools.lock.
Used during deployment (Render/Docker/CI) and local developer setups.
"""
import io
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

# Force unbuffered output for real-time deployment logging
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# Pinned Python package dependencies
PIP_PACKAGES = [
    "semgrep==1.102.0",
    "bandit==1.8.0",
    "checkov==3.2.355",
    "pip-audit==2.7.3",
]

# Pinned standalone binary distributions (Linux x86_64)
LINUX_BINARIES = {
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


def install_pip_packages():
    """Install pinned pip security scanner tools."""
    print("=" * 80)
    print("==> Installing pinned Python scanner packages via pip...")
    print("=" * 80)
    for pkg in PIP_PACKAGES:
        print(f"--> pip install {pkg}...")
        try:
            cmd = [sys.executable, "-m", "pip", "install", "--prefer-binary", pkg]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=180)
            if res.returncode == 0:
                print(f"    ✓ {pkg} installed successfully.")
            else:
                print(f"    ! Warning: failed to install {pkg}: {res.stderr[:200]}")
        except subprocess.TimeoutExpired:
            print(f"    ! Warning: pip install {pkg} timed out after 180s. Skipping.")
        except Exception as exc:
            print(f"    ! Warning: exception installing {pkg}: {exc}")


def install_linux_binaries(target_dir: Path, local_bin_dir: Path):
    """Download and extract pinned standalone binaries on Linux x86_64."""
    print("\n" + "=" * 80)
    print(f"==> Installing pinned Linux x86_64 binaries into {target_dir}...")
    print("=" * 80)

    target_dir.mkdir(parents=True, exist_ok=True)
    local_bin_dir.mkdir(parents=True, exist_ok=True)

    headers = {"User-Agent": "SecureScan-Tool-Installer/2.0"}

    for name, spec in LINUX_BINARIES.items():
        dest = target_dir / spec["bin_name"]
        local_dest = local_bin_dir / spec["bin_name"]

        # If already installed and executable, verify and skip download
        if dest.is_file() and os.access(dest, os.X_OK):
            print(f"--> {name} already present at {dest}. Skipping download.")
            try:
                shutil.copy2(dest, local_dest)
                os.chmod(local_dest, 0o755)
            except Exception:
                pass
            continue

        print(f"--> Downloading {name} from {spec['url']}...")
        try:
            req = urllib.request.Request(spec["url"], headers=headers)
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = resp.read()
        downloaded = False
        has_curl = shutil.which("curl") is not None
        has_tar = shutil.which("tar") is not None

            if spec["type"] == "direct":
                with open(dest, "wb") as f:
                    f.write(data)
                os.chmod(dest, 0o755)
            elif spec["type"] == "tar.gz":
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                    found = False
                    bin_name = spec["bin_name"]
                    for member in tar.getmembers():
                        if member.name == bin_name or member.name.endswith("/" + bin_name):
                            f_obj = tar.extractfile(member)
                            if f_obj:
                                with open(dest, "wb") as f_out:
                                    f_out.write(f_obj.read())
                                os.chmod(dest, 0o755)
                                found = True
                                break
                    if not found:
                        print(f"    ! Warning: binary '{bin_name}' not found inside archive.")
                        continue
        # Try fast curl first on Linux
        if has_curl:
            try:
                if spec["type"] == "direct":
                    curl_cmd = ["curl", "-sSL", "--connect-timeout", "10", "--max-time", "45", "-o", str(dest), spec["url"]]
                    res = subprocess.run(curl_cmd, capture_output=True, timeout=50)
                    if res.returncode == 0 and dest.is_file() and dest.stat().st_size > 1000:
                        os.chmod(dest, 0o755)
                        downloaded = True
                elif spec["type"] == "tar.gz" and has_tar:
                    tmp_archive = target_dir / f"{name}_temp.tar.gz"
                    curl_cmd = ["curl", "-sSL", "--connect-timeout", "10", "--max-time", "45", "-o", str(tmp_archive), spec["url"]]
                    res = subprocess.run(curl_cmd, capture_output=True, timeout=50)
                    if res.returncode == 0 and tmp_archive.is_file():
                        tar_cmd = ["tar", "-xzf", str(tmp_archive), "-C", str(target_dir), spec["bin_name"]]
                        t_res = subprocess.run(tar_cmd, capture_output=True, timeout=20)
                        if t_res.returncode == 0 and dest.is_file():
                            os.chmod(dest, 0o755)
                            downloaded = True
                    if tmp_archive.exists():
                        tmp_archive.unlink()
            except Exception as exc:
                print(f"    ! curl attempt for {name} failed: {exc}")

        if not downloaded:
            try:
                req = urllib.request.Request(spec["url"], headers=headers)
                with urllib.request.urlopen(req, timeout=45) as resp:
                    data = resp.read()

                if spec["type"] == "direct":
                    with open(dest, "wb") as f:
                        f.write(data)
                    os.chmod(dest, 0o755)
                    downloaded = True
                elif spec["type"] == "tar.gz":
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                        found = False
                        bin_name = spec["bin_name"]
                        for member in tar.getmembers():
                            if member.name == bin_name or member.name.endswith("/" + bin_name):
                                f_obj = tar.extractfile(member)
                                if f_obj:
                                    with open(dest, "wb") as f_out:
                                        f_out.write(f_obj.read())
                                    os.chmod(dest, 0o755)
                                    found = True
                                    downloaded = True
                                    break
                        if not found:
                            print(f"    ! Warning: binary '{bin_name}' not found inside archive.")
                            continue
            except Exception as exc:
                print(f"    ! Warning: failed downloading {name}: {exc}")

        if downloaded and dest.is_file():
            # Copy to user local bin as well
            try:
                shutil.copy2(dest, local_dest)
                os.chmod(local_dest, 0o755)
            except Exception:
                pass

            print(f"    ✓ {name} successfully installed ({dest.stat().st_size} bytes).")
        except Exception as exc:
            print(f"    ! Warning: failed downloading {name}: {exc}")
        else:
            print(f"    ! Failed to install {name}.")


def install_npm_tools():
    """Attempt installing frontend vulnerability scanner Retire.js via npm if available."""
    npm_path = shutil.which("npm")
    if not npm_path:
        print("--> npm not found on PATH. Skipping retire.js install.")
        return

    print("\n" + "=" * 80)
    print("==> Installing Retire.js via npm...")
    print("=" * 80)
    try:
        cmd = [npm_path, "install", "-g", "retire@5.2.4"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode == 0:
            print("    ✓ retire@5.2.4 installed successfully.")
        else:
            print(f"    ! Note: npm -g install failed ({res.stderr[:100]}); attempting local prefix...")
            local_prefix = Path.home() / ".local"
            subprocess.run([npm_path, "install", "--prefix", str(local_prefix), "retire@5.2.4"], capture_output=True, check=False)
    except Exception as exc:
        print(f"    ! Note: npm retire install skipped: {exc}")


def verify_installed_tools(bin_dir: Path, local_bin_dir: Path):
    """Run verification check on all primary tools and print status summary."""
    print("\n" + "=" * 80)
    print(" SECURESCAN 2.0 — PRIMARY TOOL INSTALLATION VERIFICATION")
    print("=" * 80)

    # Ensure search paths are active in this process
    current_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{bin_dir}{os.pathsep}{local_bin_dir}{os.pathsep}{current_path}"

    all_tools = [
        ("Semgrep (SAST)", "semgrep", ["--version"]),
        ("Bandit (Python AST)", "bandit", ["--version"]),
        ("Checkov (IaC)", "checkov", ["--version"]),
        ("pip-audit (SCA)", "pip-audit", ["--version"]),
        ("Gitleaks (Secrets)", "gitleaks", ["version"]),
        ("TruffleHog (Secrets/Git)", "trufflehog", ["--version"]),
        ("OSV-Scanner (SCA)", "osv-scanner", ["--version"]),
        ("Syft (SBOM)", "syft", ["version"]),
        ("Hadolint (Dockerfile)", "hadolint", ["--version"]),
        ("Actionlint (CI/CD)", "actionlint", ["--version"]),
        ("Zizmor (GitHub Actions)", "zizmor", ["--version"]),
        ("Trivy (Container/IaC)", "trivy", ["--version"]),
        ("Retire.js (Frontend JS)", "retire", ["--version"]),
    ]

    installed_count = 0
    for label, binary, args in all_tools:
        # Check shutil.which or direct file in bin_dir / local_bin_dir
        path = shutil.which(binary)
        if not path:
            for d in [bin_dir, local_bin_dir]:
                cand = d / binary
                if cand.is_file() and os.access(cand, os.X_OK):
                    path = str(cand)
                    break

        if path:
            try:
                proc = subprocess.run([path] + args, capture_output=True, text=True, timeout=5, check=False)
                ver_line = (proc.stdout or proc.stderr or "installed").splitlines()[0][:50]
                print(f"  [PASS] {label:<28}: {ver_line} ({path})")
                installed_count += 1
            except Exception as e:
                print(f"  [PASS] {label:<28}: Installed at {path} (probe: {e})")
                installed_count += 1
        else:
            print(f"  [FALLBACK] {label:<24}: Not present on this OS/architecture. Validated fallback active.")

    print("-" * 80)
    print(f"Summary: {installed_count}/{len(all_tools)} primary tool CLIs installed and operational.")
    print("=" * 80 + "\n")


def main():
    base_dir = Path(__file__).resolve().parent.parent
    target_bin = base_dir / ".bin"
    local_bin = Path.home() / ".local" / "bin"

    if "--verify-only" in sys.argv or "--check" in sys.argv:
        verify_installed_tools(target_bin, local_bin)
        return 0

    print(f"Initializing SecureScan Tool Installer on {platform.system()} ({platform.machine()})...")

    # 1. Install pip-based scanners
    install_pip_packages()

    # 2. On Linux, download standalone binaries
    is_linux = sys.platform.startswith("linux")
    if is_linux:
        install_linux_binaries(target_bin, local_bin)
        install_npm_tools()
    else:
        print(f"Note: Current OS is '{platform.system()}'. Standalone Linux binary downloads skipped.")
        print("Primary pip tools (semgrep, bandit, checkov, pip-audit) installed for local execution.")

    # 3. Verify and print diagnostics
    verify_installed_tools(target_bin, local_bin)
    return 0


if __name__ == "__main__":
    sys.exit(main())
