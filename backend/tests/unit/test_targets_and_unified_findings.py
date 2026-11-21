"""Tests for Step 3: Unified Finding Engine, Target Management, Verification, and Scope Boundaries."""
import shutil
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.db import Base
from app.core.errors import (
    TargetNotFoundError,
    TargetNotVerifiedError,
    OutOfScopeError,
    ConsentRequiredError,
    SSRFBlockedError
)
from app.core.safe_fetch import is_safe_url
from app.models.models import (
    TargetModel,
    TargetVerificationModel,
    ScanScopeModel,
    ConsentRecordModel,
    FindingModel,
    AuditModel,
    RepositoryModel
)
from app.schemas.enums import Severity, Confidence, ScannerName
from app.schemas.finding import FindingCreate
from app.services.finding_engine import (
    generate_finding_fingerprint,
    correlate_and_deduplicate_findings,
    enrich_standards_mapping,
    compute_unified_priority
)
from app.services.targets import (
    register_target,
    create_verification_challenge,
    verify_target_ownership,
    record_scan_consent,
    configure_scan_scope,
    is_url_in_scope,
    assert_target_can_be_scanned
)


# ==============================================================================
# Gate (a): Active scan is rejected for unverified target
# ==============================================================================
def test_gate_a_active_scan_rejected_for_unverified_target(db_session):
    """Confirm active scanning is hard-rejected when target is unverified."""
    session_id = f"test-sess-{uuid.uuid4().hex[:8]}"
    target = register_target(
        db=db_session,
        session_id=session_id,
        url="https://app.example.com",
        target_type="WEBSITE"
    )
    assert target.verified is False

    # Passive inspection allowed
    assert_target_can_be_scanned(db_session, target.id, requires_active_testing=False)

    # Active scanning MUST raise TargetNotVerifiedError
    with pytest.raises(TargetNotVerifiedError) as exc_info:
        assert_target_can_be_scanned(db_session, target.id, requires_active_testing=True)
    assert "not ownership-verified" in str(exc_info.value).lower()

    # Create verification challenge
    challenge = create_verification_challenge(db_session, target.id, method="DNS_TXT")
    assert challenge.token.startswith("securescan-")
    assert challenge.status == "PENDING"

    # Still rejected while PENDING
    with pytest.raises(TargetNotVerifiedError):
        assert_target_can_be_scanned(db_session, target.id, requires_active_testing=True)

    # Verify ownership with valid proof
    verified = verify_target_ownership(
        db_session,
        target.id,
        verification_id=challenge.id,
        mock_proof={"token": challenge.token}
    )
    assert verified is True
    assert target.verified is True

    # Even if verified, active testing still requires consent
    with pytest.raises(ConsentRequiredError):
        assert_target_can_be_scanned(db_session, target.id, requires_active_testing=True)

    # Once consent is recorded, active scan is allowed
    record_scan_consent(
        db=db_session,
        target_id=target.id,
        user_id="sec-admin@example.com",
        client_ip="198.51.100.1"
    )
    allowed_target = assert_target_can_be_scanned(db_session, target.id, requires_active_testing=True)
    assert allowed_target.id == target.id

    # 30-day currency expiration check
    target.verified_at = datetime.utcnow() - timedelta(days=31)
    db_session.commit()
    with pytest.raises(TargetNotVerifiedError) as exp_info:
        assert_target_can_be_scanned(db_session, target.id, requires_active_testing=True)
    assert "expired" in str(exp_info.value).lower()


# ==============================================================================
# Gate (b): Loopback, private IP, cloud metadata, & gov domains blocked
# ==============================================================================
def test_gate_b_ssrf_and_government_domains_blocked(db_session):
    """
    Ensure is_safe_url strictly blocks:
    - Loopback (127.0.0.1, localhost)
    - Cloud metadata (169.254.169.254)
    - Private IP ranges (10.0.0.1, 192.168.1.1, 172.16.0.1)
    - Government and defense domains (.gov.in, .nic.in, .mil, .gov)
    """
    blocked_urls = [
        "http://127.0.0.1:8000/api",
        "http://localhost:3000",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254.nip.io",
        "http://10.0.0.1/admin",
        "http://192.168.1.1/router",
        "http://172.16.0.5/api",
        "https://uidai.gov.in",
        "https://parivahan.gov.in/portal",
        "https://cert-in.nic.in",
        "https://delhipolice.nic.in",
        "https://army.mil",
        "https://defense.gov",
    ]

    for url in blocked_urls:
        safe, reason = is_safe_url(url)
        assert safe is False, f"Expected {url} to be blocked, but was marked safe! Reason: {reason}"
        assert reason is not None

        # Confirm register_target raises SSRFBlockedError
        with pytest.raises(SSRFBlockedError):
            register_target(
                db=db_session,
                session_id="test-session",
                url=url
            )

    # Valid public target should be permitted
    safe, reason = is_safe_url("https://example.com/api")
    assert safe is True


# ==============================================================================
# Gate (c): Deduplication & multi-tool signal merging
# ==============================================================================
def test_gate_c_duplicate_findings_merge_with_multiple_signals():
    """
    Confirm that two findings with matching CWE and location from different tools
    merge into a single unified finding containing both provenance signals.
    """
    f1 = {
        "rule_id": "python.lang.security.audit.sqli",
        "tool": "semgrep",
        "scanner_name": "semgrep",
        "category": "security",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "title": "SQL Injection in user authentication",
        "description": "Raw concatenation in SQL query",
        "file_path": "app/auth.py",
        "start_line": 42,
        "end_line": 45,
        "cwe_ids": ["CWE-89"],
        "owasp_refs": ["A03:2021-Injection"],
        "exposure": "public",
        "data_sensitivity": "credentials"
    }

    f2 = {
        "rule_id": "B608:hardcoded_sql_expressions",
        "tool": "bandit",
        "scanner_name": "bandit",
        "category": "security",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "title": "Hardcoded SQL statement execution",
        "description": "Possible SQL injection vector via string formatting",
        "file_path": "app/auth.py",
        "start_line": 42,
        "end_line": 45,
        "cwe_ids": ["CWE-89"],
        "owasp_refs": ["A03:2021-Injection"],
        "exposure": "public",
        "data_sensitivity": "credentials"
    }

    audit_id = "test-audit-123"
    merged = correlate_and_deduplicate_findings([f1, f2], audit_id=audit_id)
    assert len(merged) == 1

    unified = merged[0]
    assert unified["audit_id"] == audit_id
    assert unified["severity"] == "CRITICAL"  # Upgraded to higher severity

    # Both scanner signals must be present
    signals = unified.get("signals") or []
    assert any("semgrep" in s.lower() for s in signals)
    assert any("bandit" in s.lower() for s in signals)

    # Priority computation: CRITICAL + CONFIRMED + public + credentials => P0
    assert unified["priority"] == "P0"

    # Enriched standards mapping
    standards = unified.get("standards") or {}
    assert "cwe" in standards
    assert "CWE-89" in standards["cwe"]


# ==============================================================================
# Gate (d): Database Migration 003 Upgrade & Downgrade Integrity
# ==============================================================================
def test_gate_d_migration_003_upgrade_and_downgrade(tmp_path):
    """
    Verify Alembic migration 003 runs cleanly on a SQLite database,
    supports both downgrade (-1) and re-upgrade without data corruption.
    """
    from alembic import command
    from alembic.config import Config

    db_copy = tmp_path / "test_migration.db"
    db_url = f"sqlite:///{db_copy.as_posix()}"

    alembic_cfg = Config(settings.BASE_DIR / "backend" / "alembic.ini")
    alembic_cfg.set_main_option("script_location", str(settings.BASE_DIR / "backend" / "migrations"))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    # 1. Run migrations to head
    command.upgrade(alembic_cfg, "head")

    test_engine = create_engine(db_url)
    with test_engine.connect() as conn:
        tables = conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t[0] for t in tables]
        assert "targets" in table_names
        assert "target_verifications" in table_names
        assert "scan_scopes" in table_names
        assert "consent_records" in table_names

        # Verify added columns in findings
        finding_cols = [c[1] for c in conn.exec_driver_sql("PRAGMA table_info(findings)").fetchall()]
        assert "signals" in finding_cols
        assert "priority" in finding_cols
        assert "standards" in finding_cols

    # 2. Downgrade to 002
    command.downgrade(alembic_cfg, "002_add_tool_runs_table")
    with test_engine.connect() as conn:
        tables_after_down = [t[0] for t in conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "targets" not in tables_after_down
        assert "tool_runs" in tables_after_down  # Migration 002 table intact

    # 3. Re-upgrade to head
    command.upgrade(alembic_cfg, "head")
    with test_engine.connect() as conn:
        tables_reup = [t[0] for t in conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "targets" in tables_reup
        assert "target_verifications" in tables_reup


# ==============================================================================
# Scope enforcement & excluded safety paths
# ==============================================================================
def test_scope_enforcement_and_excluded_paths(db_session):
    """Test allowed hosts and dangerous safety exclusions (/logout, /billing, /admin/wipe)."""
    target = register_target(db_session, "sess-1", "https://api.example.com", "API")
    scope = configure_scan_scope(
        db=db_session,
        target_id=target.id,
        allowed_hosts=["api.example.com"],
        allowed_paths=["/v1", "/api"],
        excluded_paths=["/admin/delete", "/private"],
        max_rps=10,
        max_crawl_depth=2
    )

    # Allowed endpoint
    in_scope, _ = is_url_in_scope("https://api.example.com/v1/users", scope)
    assert in_scope is True

    # Out of scope host
    in_scope, reason = is_url_in_scope("https://other.example.com/v1/users", scope)
    assert in_scope is False
    assert "outside allowed scope hosts" in reason

    # Out of scope path
    in_scope, reason = is_url_in_scope("https://api.example.com/v2/items", scope)
    assert in_scope is False
    assert "not within permitted allowed paths" in reason

    # Hard-blocked dangerous default excluded path (/logout)
    in_scope, reason = is_url_in_scope("https://api.example.com/v1/logout", scope)
    assert in_scope is False
    assert "matches excluded safety path" in reason

    # Custom excluded path
    in_scope, reason = is_url_in_scope("https://api.example.com/v1/private/key", scope)
    assert in_scope is False
    assert "matches excluded safety path" in reason
