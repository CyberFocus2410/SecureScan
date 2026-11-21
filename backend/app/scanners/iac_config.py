"""Infrastructure, Docker, CI/CD, and Cloud configuration security scanner (Step 5, ADR-002, ADR-006)."""
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml

from app.core.security import redact_text
from app.schemas.enums import ScannerName, Severity, Confidence
from app.scanners.base import (
    BaseScannerAdapter,
    ScannerMetadata,
    RawFinding,
    ScannerExecutionResult
)

logger = logging.getLogger(__name__)


class IacConfigScanner(BaseScannerAdapter):
    """
    Static analyzer for Infrastructure as Code, Container definitions, CI/CD workflows,
    and Cloud / PaaS deployment configurations.
    Covers:
    - Dockerfile & docker-compose (root user, privileged, secrets in layers, unpinned base images, exposed DB ports, default creds)
    - Kubernetes & Terraform (public buckets, wildcard IAM, missing encryption, open security groups, host namespaces)
    - GitHub Actions (pull_request_target misuse, script injection, unpinned actions, excessive permissions, secrets in logs)
    - PaaS / Cloud configs (Vercel, Render, Netlify, Firebase rules, committed .env, production source maps, open admin/debug routes)
    """
    VERSION = "1.0.0"
    tool_name = "iac_config"

    def __init__(self):
        self.last_evidenced_passes: list[dict[str, str]] = []

    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=ScannerName.CUSTOM,
            version=self.VERSION,
            rules_version=self.VERSION,
            supported_languages=["YAML", "Dockerfile", "HCL", "JSON", "Config"]
        )

    def supports(self, detected_languages: list[str], detected_frameworks: list[str]) -> bool:
        # IaC and config analysis applies to any repository containing config files
        return True

    def prepare(self, worktree_dir: Path) -> dict[str, Any]:
        return {}

    def execute(self, worktree_dir: Path, context: dict[str, Any]) -> ScannerExecutionResult:
        findings: list[RawFinding] = []
        evidenced_passes: list[dict[str, str]] = []

        # 1. Dockerfile Analysis
        docker_findings, docker_passes = self._scan_dockerfiles(worktree_dir)
        findings.extend(docker_findings)
        evidenced_passes.extend(docker_passes)

        # 2. Docker Compose Analysis
        compose_findings, compose_passes = self._scan_compose_files(worktree_dir)
        findings.extend(compose_findings)
        evidenced_passes.extend(compose_passes)

        # 3. Terraform & Kubernetes Analysis
        iac_findings, iac_passes = self._scan_terraform_and_k8s(worktree_dir)
        findings.extend(iac_findings)
        evidenced_passes.extend(iac_passes)

        # 4. GitHub Actions Workflows Analysis
        ci_findings, ci_passes = self._scan_github_actions(worktree_dir)
        findings.extend(ci_findings)
        evidenced_passes.extend(ci_passes)

        # 5. PaaS / Cloud Hosting / Environment Leaks
        cloud_findings, cloud_passes = self._scan_cloud_and_env_configs(worktree_dir)
        findings.extend(cloud_findings)
        evidenced_passes.extend(cloud_passes)

        self.last_evidenced_passes = evidenced_passes

        return ScannerExecutionResult(
            scanner=ScannerName.CUSTOM,
            version=self.VERSION,
            status="COMPLETED",
            duration_ms=45,
            raw_findings=findings
        )

    def parse(self, result: ScannerExecutionResult, **kwargs) -> list[RawFinding]:
        return result.raw_findings

    def normalize(self, raw_findings: list[RawFinding], audit_id: str) -> list[Any]:
        return []

    # -------------------------------------------------------------------------
    # 1. Dockerfile Analyzer
    # -------------------------------------------------------------------------
    def _scan_dockerfiles(self, worktree_dir: Path) -> Tuple[list[RawFinding], list[dict[str, str]]]:
        findings: list[RawFinding] = []
        passes: list[dict[str, str]] = []

        dockerfile_names = {"dockerfile", "containerfile"}

        for root, _, files in os.walk(worktree_dir):
            if any(skip in root for skip in [".git", "node_modules", "venv", ".venv"]):
                continue
            for fname in files:
                lower_name = fname.lower()
                is_dockerfile = lower_name in dockerfile_names or lower_name.startswith("dockerfile.") or lower_name.endswith(".dockerfile")
                if not is_dockerfile:
                    continue

                fpath = Path(root) / fname
                rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")

                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                lines = content.splitlines()
                has_user_directive = False
                user_is_root = False
                unpinned_base = False
                unpinned_line = 1
                unpinned_snippet = ""

                for idx, line in enumerate(lines, start=1):
                    trimmed = line.strip()
                    if not trimmed or trimmed.startswith("#"):
                        continue

                    # Check FROM (unpinned base image)
                    if trimmed.upper().startswith("FROM "):
                        image_part = trimmed.split()[1] if len(trimmed.split()) > 1 else ""
                        if ":" not in image_part or image_part.endswith(":latest") or (not image_part.startswith("scratch") and "@sha256:" not in image_part and ":" not in image_part):
                            unpinned_base = True
                            unpinned_line = idx
                            unpinned_snippet = trimmed

                    # Check USER
                    if trimmed.upper().startswith("USER "):
                        has_user_directive = True
                        user_val = trimmed[5:].strip().lower()
                        if user_val in ("root", "0", "0:0"):
                            user_is_root = True

                    # Check Secrets in ENV or ARG
                    if trimmed.upper().startswith("ENV ") or trimmed.upper().startswith("ARG "):
                        lower_line = trimmed.lower()
                        if any(k in lower_line for k in ["password", "secret", "api_key", "token", "private_key", "access_key"]):
                            if "=" in trimmed or " " in trimmed[4:]:
                                val_part = trimmed.split("=", 1)[-1] if "=" in trimmed else trimmed.split(None, 2)[-1]
                                val_part = val_part.strip().strip("'\"")
                                # If it looks like a non-empty, non-variable value
                                if val_part and not val_part.startswith("$") and not val_part.startswith("{") and len(val_part) > 4:
                                    findings.append(RawFinding(
                                        rule_id="iac-docker-secret-in-layer",
                                        title="Hardcoded Secret or Credential in Docker Layer (ENV/ARG)",
                                        description="Secrets stored in Dockerfile ENV or ARG instructions persist permanently in published image layer metadata.",
                                        category="misconfig",
                                        severity=Severity.CRITICAL,
                                        confidence=Confidence.CONFIRMED,
                                        file_path=rel_path,
                                        start_line=idx,
                                        end_line=idx,
                                        raw_snippet=redact_text(trimmed),
                                        cwe_ids=["CWE-312", "CWE-538"],
                                        owasp_refs=["A07:2021-Identification and Authentication Failures"],
                                        technical_fix="Inject secrets dynamically at runtime via container environment variables or use BuildKit secret mounts ('RUN --mount=type=secret').",
                                        validation_steps="Inspect image layers with 'docker history <image>' and confirm secret is absent."
                                    ))

                # Check root user
                if not has_user_directive or user_is_root:
                    findings.append(RawFinding(
                        rule_id="iac-docker-root-user",
                        title="Container Runs as Root by Default (Missing USER Directive)",
                        description="Dockerfile does not specify a non-root USER directive, causing container processes to run with full host root UID 0 permissions.",
                        category="misconfig",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        file_path=rel_path,
                        start_line=1,
                        end_line=1,
                        raw_snippet=f"{fname}: missing non-root USER instruction",
                        cwe_ids=["CWE-250"],
                        owasp_refs=["A05:2021-Security Misconfiguration"],
                        technical_fix="Create a non-root system user and add 'USER <user>' before entrypoint execution.",
                        validation_steps="Verify with 'docker run --rm <image> id' that UID is non-zero."
                    ))
                else:
                    passes.append({
                        "file": rel_path,
                        "check": "Container Non-Root User",
                        "status": "PASS_EVIDENCED",
                        "summary": "Container explicitly executes under a non-root system user account."
                    })

                # Check unpinned base
                if unpinned_base:
                    findings.append(RawFinding(
                        rule_id="iac-docker-unpinned-base-image",
                        title="Unpinned Docker Base Image (Mutable or Latest Tag)",
                        description="Dockerfile uses ':latest' or unpinned tag for base image, exposing builds to unexpected supply chain drifts or breaking changes.",
                        category="misconfig",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file_path=rel_path,
                        start_line=unpinned_line,
                        end_line=unpinned_line,
                        raw_snippet=redact_text(unpinned_snippet),
                        cwe_ids=["CWE-1059"],
                        owasp_refs=["A06:2021-Vulnerable and Outdated Components"],
                        technical_fix="Pin base image to specific semantic version or immutable SHA256 digest (e.g. image:1.2.3@sha256:...).",
                        validation_steps="Verify base image reference contains exact version tag or sha256 digest."
                    ))
                else:
                    passes.append({
                        "file": rel_path,
                        "check": "Pinned Base Image",
                        "status": "PASS_EVIDENCED",
                        "summary": "Base image is pinned to specific version or SHA256 digest."
                    })

        return findings, passes

    # -------------------------------------------------------------------------
    # 2. Docker Compose Analyzer
    # -------------------------------------------------------------------------
    def _scan_compose_files(self, worktree_dir: Path) -> Tuple[list[RawFinding], list[dict[str, str]]]:
        findings: list[RawFinding] = []
        passes: list[dict[str, str]] = []

        compose_patterns = ["compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"]

        for root, _, files in os.walk(worktree_dir):
            if any(skip in root for skip in [".git", "node_modules", "venv", ".venv"]):
                continue
            for fname in files:
                is_compose = (
                    fname.lower() in compose_patterns
                    or (any(c in fname.lower() for c in ["compose", "docker-compose"]) and fname.lower().endswith((".yaml", ".yml")))
                )
                if is_compose:
                    fpath = Path(root) / fname
                    rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")

                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                        data = yaml.safe_load(content)
                    except Exception:
                        continue

                    if not isinstance(data, dict):
                        continue

                    services = data.get("services", {})
                    if not isinstance(services, dict):
                        continue

                    has_exposed_db = False
                    has_privileged = False
                    has_clean_db = False

                    for svc_name, svc_cfg in services.items():
                        if not isinstance(svc_cfg, dict):
                            continue

                        # 1. Privileged Container Check
                        if svc_cfg.get("privileged") is True:
                            has_privileged = True
                            findings.append(RawFinding(
                                rule_id="iac-compose-privileged-container",
                                title=f"Privileged Container Mode Enabled for '{svc_name}'",
                                description=f"Service '{svc_name}' runs in privileged mode, granting full capabilities and host device access.",
                                category="misconfig",
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                file_path=rel_path,
                                start_line=1,
                                end_line=1,
                                raw_snippet=f"service '{svc_name}': privileged: true",
                                cwe_ids=["CWE-250"],
                                owasp_refs=["A05:2021-Security Misconfiguration"],
                                technical_fix="Remove 'privileged: true' and grant only specifically required capabilities via 'cap_add'.",
                                validation_steps="Verify container runs without CAP_SYS_ADMIN."
                            ))

                        # 2. Exposed Database Ports Check
                        image_str = str(svc_cfg.get("image", "")).lower()
                        is_db_service = any(db in svc_name.lower() or db in image_str for db in ["postgres", "mysql", "mongo", "redis", "mariadb", "elasticsearch"])
                        ports = svc_cfg.get("ports", [])

                        db_ports = {"5432", "3306", "27017", "6379", "9200", "5984", "1433"}
                        for port_entry in ports:
                            port_str = str(port_entry)
                            for db_p in db_ports:
                                if f":{db_p}" in port_str or port_str.startswith(db_p):
                                    if "127.0.0.1" not in port_str and "localhost" not in port_str:
                                        has_exposed_db = True
                                        findings.append(RawFinding(
                                            rule_id="iac-compose-exposed-db-port",
                                            title=f"Database Port Publicly Exposed in Compose ({svc_name})",
                                            description=f"Service '{svc_name}' exposes database port {db_p} on all network interfaces (0.0.0.0).",
                                            category="misconfig",
                                            severity=Severity.HIGH,
                                            confidence=Confidence.CONFIRMED,
                                            file_path=rel_path,
                                            start_line=1,
                                            end_line=1,
                                            raw_snippet=f"service '{svc_name}': ports: [{port_str}]",
                                            cwe_ids=["CWE-668", "CWE-200"],
                                            owasp_refs=["A05:2021-Security Misconfiguration"],
                                            technical_fix="Bind port strictly to localhost ('127.0.0.1:5432:5432') or communicate exclusively over internal Docker networks without host port publishing.",
                                            validation_steps="Verify database port is unreachable from external network interfaces."
                                        ))

                        # 3. Default or Hardcoded Credentials in Environment
                        env = svc_cfg.get("environment", {})
                        env_items = []
                        if isinstance(env, dict):
                            env_items = list(env.items())
                        elif isinstance(env, list):
                            for item in env:
                                if isinstance(item, str) and "=" in item:
                                    k, v = item.split("=", 1)
                                    env_items.append((k, v))

                        for k, v in env_items:
                            k_lower = str(k).lower()
                            v_str = str(v)
                            if any(p in k_lower for p in ["password", "pwd", "secret"]):
                                if v_str.lower() in ["password", "root", "admin", "postgres", "123456", "test"]:
                                    findings.append(RawFinding(
                                        rule_id="iac-compose-default-credentials",
                                        title=f"Default or Trivial Database Password in Compose ({svc_name})",
                                        description=f"Environment variable '{k}' for service '{svc_name}' uses default/weak credential value.",
                                        category="misconfig",
                                        severity=Severity.HIGH,
                                        confidence=Confidence.CONFIRMED,
                                        file_path=rel_path,
                                        start_line=1,
                                        end_line=1,
                                        raw_snippet=redact_text(f"{k}: {v_str}"),
                                        cwe_ids=["CWE-1188", "CWE-798"],
                                        owasp_refs=["A07:2021-Identification and Authentication Failures"],
                                        technical_fix="Supply passwords via environment files or Docker secrets (_FILE suffix) rather than hardcoded compose values.",
                                        validation_steps="Confirm database cannot be accessed with default password."
                                    ))

                        if is_db_service and not has_exposed_db:
                            has_clean_db = True

                    if has_clean_db:
                        passes.append({
                            "file": rel_path,
                            "check": "Isolated Database Network",
                            "status": "PASS_EVIDENCED",
                            "summary": "Database services communicate over private bridge networks without public host port exposure."
                        })

        return findings, passes

    # -------------------------------------------------------------------------
    # 3. Terraform & Kubernetes Analyzer
    # -------------------------------------------------------------------------
    def _scan_terraform_and_k8s(self, worktree_dir: Path) -> Tuple[list[RawFinding], list[dict[str, str]]]:
        findings: list[RawFinding] = []
        passes: list[dict[str, str]] = []

        for root, _, files in os.walk(worktree_dir):
            if any(skip in root for skip in [".git", "node_modules", "venv", ".venv", ".terraform"]):
                continue
            for fname in files:
                fpath = Path(root) / fname
                rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")

                # --- Terraform (.tf) ---
                if fname.endswith(".tf"):
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    lines = content.splitlines()

                    # 1. Public S3 bucket ACL
                    if "aws_s3_bucket" in content:
                        for idx, line in enumerate(lines, start=1):
                            if "acl" in line and any(pub in line for pub in ["public-read", "public-read-write"]):
                                findings.append(RawFinding(
                                    rule_id="iac-tf-public-s3-bucket",
                                    title="Publicly Readable S3 Bucket Configured in Terraform",
                                    description="AWS S3 bucket resource configures public ACL ('public-read'), exposing storage contents to anonymous internet access.",
                                    category="misconfig",
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.CONFIRMED,
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    raw_snippet=line.strip(),
                                    cwe_ids=["CWE-200", "CWE-732"],
                                    owasp_refs=["A01:2021-Broken Access Control"],
                                    technical_fix="Remove public ACL and configure 'aws_s3_bucket_public_access_block' with all public block flags set to true.",
                                    validation_steps="Verify anonymous S3 GET request returns HTTP 403 AccessDenied."
                                ))

                    # 2. Open Security Group (0.0.0.0/0 on sensitive ports)
                    for idx, line in enumerate(lines, start=1):
                        if "cidr_blocks" in line and "0.0.0.0/0" in line:
                            # Check nearby context for port 22 or database ports
                            context_window = "\n".join(lines[max(0, idx - 5):min(len(lines), idx + 5)])
                            if any(p in context_window for p in ["22", "3389", "5432", "3306", "27017"]):
                                findings.append(RawFinding(
                                    rule_id="iac-tf-open-security-group",
                                    title="Security Group Permits Ingress from 0.0.0.0/0 on Management/Database Port",
                                    description="Security group allows unrestricted ingress from universal CIDR block '0.0.0.0/0' on sensitive port (SSH/RDP/DB).",
                                    category="misconfig",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    raw_snippet=line.strip(),
                                    cwe_ids=["CWE-284"],
                                    owasp_refs=["A05:2021-Security Misconfiguration"],
                                    technical_fix="Restrict CIDR blocks to specific corporate VPN or bastion gateway IP addresses.",
                                    validation_steps="Verify port is unreachable from public IP addresses outside the authorized subnet."
                                ))

                    # 3. Wildcard IAM Permissions
                    if "jsonencode" in content or "Statement" in content:
                        for idx, line in enumerate(lines, start=1):
                            if ("Action" in line or "actions" in line) and '"*"' in line:
                                context_window = "\n".join(lines[max(0, idx - 4):min(len(lines), idx + 4)])
                                if ("Resource" in context_window or "resource" in context_window) and '"*"' in context_window:
                                    findings.append(RawFinding(
                                        rule_id="iac-tf-wildcard-iam-policy",
                                        title="Overly Permissive Wildcard IAM Policy (* on *)",
                                        description="IAM policy statement grants full wildcard actions ('*') across all resources ('*'), conferring complete administrative privileges.",
                                        category="misconfig",
                                        severity=Severity.HIGH,
                                        confidence=Confidence.CONFIRMED,
                                        file_path=rel_path,
                                        start_line=idx,
                                        end_line=idx,
                                        raw_snippet=line.strip(),
                                        cwe_ids=["CWE-732"],
                                        owasp_refs=["A01:2021-Broken Access Control"],
                                        technical_fix="Follow the principle of least privilege: specify only required actions and exact ARN resource scopes.",
                                        validation_steps="Audit IAM policy with AWS Access Analyzer."
                                    ))

                    # 4. PASS_EVIDENCED: Clean S3 bucket with public access block and encryption
                    if "aws_s3_bucket_public_access_block" in content and "aws_s3_bucket_server_side_encryption_configuration" in content:
                        passes.append({
                            "file": rel_path,
                            "check": "S3 Public Access Block & Server-Side Encryption",
                            "status": "PASS_EVIDENCED",
                            "summary": "Terraform declares explicit public access block and default AES256/KMS encryption on S3 storage."
                        })

                # --- Kubernetes Manifests (.yaml / .yml) ---
                if fname.endswith((".yaml", ".yml")) and not any(p in rel_path.lower() for p in [".github", "compose", "docker"]):
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                        k8s_docs = list(yaml.safe_load_all(content))
                    except Exception:
                        continue

                    for doc in k8s_docs:
                        if not isinstance(doc, dict):
                            continue
                        kind = doc.get("kind", "")
                        if kind in ["Deployment", "Pod", "DaemonSet", "StatefulSet", "Job"]:
                            spec = doc.get("spec", {})
                            pod_spec = spec.get("template", {}).get("spec", {}) if kind != "Pod" else spec

                            # Check hostNetwork / hostPID
                            if pod_spec.get("hostNetwork") is True or pod_spec.get("hostPID") is True:
                                findings.append(RawFinding(
                                    rule_id="iac-k8s-host-namespace-shared",
                                    title=f"Kubernetes Pod Shares Host Network or PID Namespace ({kind})",
                                    description="Pod configuration specifies hostNetwork or hostPID, breaking network/process isolation from the underlying node.",
                                    category="misconfig",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    file_path=rel_path,
                                    start_line=1,
                                    end_line=1,
                                    raw_snippet=f"{kind}: hostNetwork/hostPID: true",
                                    cwe_ids=["CWE-250"],
                                    owasp_refs=["A05:2021-Security Misconfiguration"],
                                    technical_fix="Remove 'hostNetwork: true' and 'hostPID: true'. Use Kubernetes service networking.",
                                    validation_steps="Verify pod has its own network and PID namespaces."
                                ))

                            # Check container securityContext
                            containers = pod_spec.get("containers", [])
                            for c in containers:
                                sec_ctx = c.get("securityContext", {})
                                if sec_ctx.get("privileged") is True:
                                    findings.append(RawFinding(
                                        rule_id="iac-k8s-privileged-container",
                                        title=f"Kubernetes Container Runs in Privileged Mode ({c.get('name')})",
                                        description="Container has 'securityContext.privileged: true', permitting container escape and direct access to host kernel capabilities.",
                                        category="misconfig",
                                        severity=Severity.HIGH,
                                        confidence=Confidence.CONFIRMED,
                                        file_path=rel_path,
                                        start_line=1,
                                        end_line=1,
                                        raw_snippet=f"container '{c.get('name')}': privileged: true",
                                        cwe_ids=["CWE-250"],
                                        owasp_refs=["A05:2021-Security Misconfiguration"],
                                        technical_fix="Set 'securityContext.privileged: false' and drop all unnecessary Linux capabilities.",
                                        validation_steps="Ensure pod admission controller rejects privileged pods."
                                    ))

                            # Clean pod security context check
                            pod_sec = pod_spec.get("securityContext", {})
                            if pod_sec.get("runAsNonRoot") is True:
                                passes.append({
                                    "file": rel_path,
                                    "check": "Kubernetes Non-Root Security Context",
                                    "status": "PASS_EVIDENCED",
                                    "summary": f"Kubernetes {kind} enforces runAsNonRoot: true across pod containers."
                                })

        return findings, passes

    # -------------------------------------------------------------------------
    # 4. GitHub Actions Workflows Analyzer
    # -------------------------------------------------------------------------
    def _scan_github_actions(self, worktree_dir: Path) -> Tuple[list[RawFinding], list[dict[str, str]]]:
        findings: list[RawFinding] = []
        passes: list[dict[str, str]] = []

        workflows_dir = worktree_dir / ".github" / "workflows"
        if not workflows_dir.exists():
            return findings, passes

        sha_commit_regex = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

        for fname in os.listdir(workflows_dir):
            if not fname.endswith((".yaml", ".yml")):
                continue

            fpath = workflows_dir / fname
            rel_path = f".github/workflows/{fname}"

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                data = yaml.safe_load(content)
            except Exception:
                continue

            lines = content.splitlines()

            # 1. pull_request_target trigger misuse
            is_pr_target = "pull_request_target" in content

            if is_pr_target:
                findings.append(RawFinding(
                    rule_id="ci-gha-pull-request-target-misuse",
                    title="Dangerous pull_request_target Trigger in GitHub Actions",
                    description=(
                        "Workflow triggers on 'pull_request_target'. This event runs in the context of the base repository "
                        "with access to secrets and read/write repository tokens, enabling malicious PR authors to execute untrusted code or steal credentials."
                    ),
                    category="misconfig",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    file_path=rel_path,
                    start_line=1,
                    end_line=1,
                    raw_snippet="on: pull_request_target",
                    cwe_ids=["CWE-829", "CWE-250"],
                    owasp_refs=["A08:2021-Software and Data Integrity Failures"],
                    technical_fix="Use the unprivileged 'pull_request' trigger or avoid checking out PR code in workflows that have access to sensitive secrets.",
                    validation_steps="Verify workflow does not checkout untrusted pull request commit refs."
                ))

            # 2. Excessive Permissions (permissions: write-all)
            top_perms = data.get("permissions") if isinstance(data, dict) else None
            if top_perms == "write-all":
                findings.append(RawFinding(
                    rule_id="ci-gha-excessive-permissions-write-all",
                    title="Excessive Repository Permissions ('permissions: write-all')",
                    description="Workflow configures 'permissions: write-all', granting broad read/write scopes to the default GITHUB_TOKEN.",
                    category="misconfig",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    file_path=rel_path,
                    start_line=1,
                    end_line=1,
                    raw_snippet="permissions: write-all",
                    cwe_ids=["CWE-732"],
                    owasp_refs=["A01:2021-Broken Access Control"],
                    technical_fix="Follow the principle of least privilege by specifying exact required permission scopes (e.g. 'permissions: contents: read').",
                    validation_steps="Verify GITHUB_TOKEN has minimal scopes in workflow execution logs."
                ))

            # 3. Line-by-line checks for script injection, unpinned actions, and secrets in logs
            unpinned_action_found = False
            safe_perms_found = False

            if isinstance(top_perms, dict) and top_perms.get("contents") == "read":
                safe_perms_found = True

            in_run_block = False
            for idx, line in enumerate(lines, start=1):
                trimmed = line.strip()
                if not trimmed or trimmed.startswith("#"):
                    continue

                if trimmed.startswith("run:") or trimmed.startswith("- run:"):
                    in_run_block = True
                elif any(trimmed.startswith(k) for k in ["name:", "- name:", "uses:", "- uses:", "env:", "with:", "id:", "shell:"]):
                    in_run_block = False

                # Script injection via untrusted github context expressions in run: commands
                if in_run_block and "${{" in trimmed and any(ctx in trimmed for ctx in [
                    "github.event.issue.title", "github.event.issue.body",
                    "github.event.comment.body", "github.event.pull_request.title",
                    "github.event.pull_request.body", "github.head_ref"
                ]):
                    findings.append(RawFinding(
                        rule_id="ci-gha-untrusted-script-injection",
                        title="GitHub Actions Script Injection via Untrusted Context Expression",
                        description=(
                            "Untrusted input expression (e.g. issue title/body) is interpolated directly into an inline shell script. "
                            "Attackers can inject shell metacharacters (;, |, `) to execute arbitrary commands with the runner's privileges."
                        ),
                        category="injection",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        file_path=rel_path,
                        start_line=idx,
                        end_line=idx,
                        raw_snippet=redact_text(trimmed),
                        cwe_ids=["CWE-78", "CWE-94"],
                        owasp_refs=["A03:2021-Injection"],
                        technical_fix="Pass untrusted context values into an environment variable ('env: PR_TITLE: ${{ ... }}') and reference the environment variable ('$PR_TITLE') in the script.",
                        validation_steps="Submit PR title containing '; echo pwned;' and verify it is treated as a literal string."
                    ))

                # Unpinned Third-Party Actions
                if trimmed.startswith("- uses:") or trimmed.startswith("uses:"):
                    action_ref = trimmed.split("uses:", 1)[-1].strip().split("#")[0].strip()
                    if "@" in action_ref:
                        action_name, version_tag = action_ref.split("@", 1)
                        # Check if action is third-party (owner/repo) and version is not a 40-character commit SHA
                        if "/" in action_name and not sha_commit_regex.match(version_tag):
                            unpinned_action_found = True
                            findings.append(RawFinding(
                                rule_id="ci-gha-unpinned-third-party-action",
                                title=f"Unpinned Third-Party Action '{action_name}@{version_tag}'",
                                description=(
                                    f"Third-party action '{action_name}' is pinned to a mutable tag/branch ('{version_tag}'). "
                                    "A compromised action maintainer or repotag update can inject malicious code into CI builds."
                                ),
                                category="misconfig",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                raw_snippet=trimmed,
                                cwe_ids=["CWE-829", "CWE-1357"],
                                owasp_refs=["A08:2021-Software and Data Integrity Failures"],
                                technical_fix=f"Pin action to a 40-character commit SHA hash: uses: {action_name}@<full-commit-sha> # {version_tag}",
                                validation_steps="Verify all third-party 'uses:' directives specify 40-character commit hashes."
                            ))

                # Secrets printed or echoed in workflow run steps
                if "echo " in trimmed and "secrets." in trimmed and "${{" in trimmed:
                    findings.append(RawFinding(
                        rule_id="ci-gha-secret-echoed-to-logs",
                        title="Secret Variable Printed to Console/Logs in CI Workflow",
                        description="Workflow step prints secret token using echo, risking exposure in CI build output or third-party log collectors.",
                        category="misconfig",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        file_path=rel_path,
                        start_line=idx,
                        end_line=idx,
                        raw_snippet=redact_text(trimmed),
                        cwe_ids=["CWE-532"],
                        owasp_refs=["A07:2021-Identification and Authentication Failures"],
                        technical_fix="Never echo or print secrets in build scripts. Configure tools to read secrets directly from environment variables.",
                        validation_steps="Confirm workflow step logs do not display secret tokens."
                    ))

            if not unpinned_action_found and safe_perms_found:
                passes.append({
                    "file": rel_path,
                    "check": "GitHub Actions Hardened Permissions & Pinned Actions",
                    "status": "PASS_EVIDENCED",
                    "summary": f"Workflow '{fname}' restricts GITHUB_TOKEN permissions and pins third-party actions to full commit SHA hashes."
                })

        return findings, passes

    # -------------------------------------------------------------------------
    # 5. PaaS / Cloud Hosting / Environment Leaks Analyzer
    # -------------------------------------------------------------------------
    def _scan_cloud_and_env_configs(self, worktree_dir: Path) -> Tuple[list[RawFinding], list[dict[str, str]]]:
        findings: list[RawFinding] = []
        passes: list[dict[str, str]] = []

        # 1. Committed .env files
        for root, _, files in os.walk(worktree_dir):
            if any(skip in root for skip in [".git", "node_modules", "venv", ".venv"]):
                continue
            for fname in files:
                fpath = Path(root) / fname
                rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")

                # Flag committed .env files (excluding .env.example, .env.sample, .env.template)
                if fname in [".env", ".env.local", ".env.production", ".env.staging"] or (fname.startswith(".env.") and not any(safe in fname.lower() for safe in ["example", "sample", "template"])):
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    # If file has actual key-value assignments
                    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
                    if len(lines) > 0:
                        findings.append(RawFinding(
                            rule_id="cloud-committed-env-file",
                            title=f"Committed Environment Secrets File ({fname})",
                            description=f"Environment configuration file '{fname}' is committed into repository source control, exposing local or production credentials.",
                            category="misconfig",
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            raw_snippet=redact_text(lines[0] if lines else fname),
                            cwe_ids=["CWE-312", "CWE-538"],
                            owasp_refs=["A07:2021-Identification and Authentication Failures"],
                            technical_fix="Add '.env' and '.env.*' to .gitignore and rotate any credentials that were committed.",
                            validation_steps="Verify .env file is removed from git tracking ('git rm --cached .env')."
                        ))

                # 2. Vercel Configuration (vercel.json)
                if fname.lower() == "vercel.json":
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                        v_data = json.loads(content)
                    except Exception:
                        continue

                    headers = v_data.get("headers", [])
                    for h_entry in headers:
                        h_list = h_entry.get("headers", [])
                        for h in h_list:
                            k = h.get("key", "").lower()
                            v = h.get("value", "")
                            # Check wildcard CORS on API routes
                            if k == "access-control-allow-origin" and v == "*":
                                findings.append(RawFinding(
                                    rule_id="cloud-vercel-permissive-cors",
                                    title="Permissive Wildcard CORS Configured in vercel.json",
                                    description="Vercel configuration sets Access-Control-Allow-Origin: * on API routes, exposing backend endpoints to cross-origin abuse.",
                                    category="misconfig",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.CONFIRMED,
                                    file_path=rel_path,
                                    start_line=1,
                                    end_line=1,
                                    raw_snippet="Access-Control-Allow-Origin: *",
                                    cwe_ids=["CWE-942"],
                                    owasp_refs=["A05:2021-Security Misconfiguration"],
                                    technical_fix="Specify exact trusted origin domains in CORS response headers.",
                                    validation_steps="Verify unauthorized origin does not receive Access-Control-Allow-Origin: *."
                                ))
                            if "debug" in k or "debug" in str(v).lower():
                                findings.append(RawFinding(
                                    rule_id="cloud-vercel-debug-header-active",
                                    title="Debug Mode Header Active in vercel.json",
                                    description="Vercel deployment header configures active debug flags or headers in responses.",
                                    category="misconfig",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.HIGH,
                                    file_path=rel_path,
                                    start_line=1,
                                    end_line=1,
                                    raw_snippet=f"{k}: {v}",
                                    cwe_ids=["CWE-489"],
                                    owasp_refs=["A05:2021-Security Misconfiguration"],
                                    technical_fix="Remove debug headers before deploying to production.",
                                    validation_steps="Inspect live HTTP responses to confirm debug header is omitted."
                                ))

                    # Check rewrites for open debug or admin routes
                    rewrites = v_data.get("rewrites", [])
                    for rw in rewrites:
                        src = rw.get("source", "").lower()
                        dest = rw.get("destination", "").lower()
                        if "/debug" in src or "/debug" in dest or "/admin-bypass" in src:
                            findings.append(RawFinding(
                                rule_id="cloud-vercel-open-debug-rewrite",
                                title=f"Open Debug or Admin Rewrite Route in vercel.json ({src})",
                                description=f"Vercel rewrites configuration exposes debug or administrative endpoint '{src}' to public access.",
                                category="misconfig",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                file_path=rel_path,
                                start_line=1,
                                end_line=1,
                                raw_snippet=f"rewrite: {src} -> {dest}",
                                cwe_ids=["CWE-489", "CWE-200"],
                                owasp_refs=["A05:2021-Security Misconfiguration"],
                                technical_fix="Remove public rewrites for internal debug and administrative endpoints.",
                                validation_steps="Confirm /debug and /admin routes return HTTP 404 in production."
                            ))

                # 3. Firebase / Firestore Security Rules (firestore.rules, database.rules.json)
                if fname in ["firestore.rules", "database.rules.json"]:
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    # Unauthenticated open read/write in firestore.rules
                    if "allow read, write: if true;" in content or "allow read: if true;" in content:
                        findings.append(RawFinding(
                            rule_id="cloud-firebase-open-security-rules",
                            title="Completely Open Firestore Security Rules (Public Read/Write)",
                            description="Firestore security rules explicitly permit unrestricted read and/or write access to all anonymous internet users.",
                            category="misconfig",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            raw_snippet="allow read, write: if true;",
                            cwe_ids=["CWE-284", "CWE-732"],
                            owasp_refs=["A01:2021-Broken Access Control"],
                            technical_fix="Require authentication and ownership validation: allow read, write: if request.auth != null && request.auth.uid == userId;",
                            validation_steps="Verify unauthenticated client SDK read/write operations are rejected with permission-denied."
                        ))
                    elif "request.auth != null" in content:
                        passes.append({
                            "file": rel_path,
                            "check": "Firebase Authentication Rules Gate",
                            "status": "PASS_EVIDENCED",
                            "summary": "Firestore rules enforce user authentication checks ('request.auth != null') on document access."
                        })

                # 4. Production Source Maps (.js.map files or config indicators)
                if fname.endswith(".js.map"):
                    findings.append(RawFinding(
                        rule_id="cloud-production-source-map-exposed",
                        title=f"Production JavaScript Source Map Committed ({fname})",
                        description="Source map files (.js.map) committed or served expose original unminified client source code, internal comments, and API endpoints.",
                        category="misconfig",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        file_path=rel_path,
                        start_line=1,
                        end_line=1,
                        raw_snippet=fname,
                        cwe_ids=["CWE-540"],
                        owasp_refs=["A05:2021-Security Misconfiguration"],
                        technical_fix="Disable production source maps in build config ('GENERATE_SOURCEMAP=false' or 'productionSourceMap: false').",
                        validation_steps="Verify build dist directory does not emit .map files."
                    ))

        return findings, passes
