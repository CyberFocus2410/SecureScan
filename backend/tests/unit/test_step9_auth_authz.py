"""Unit tests for Step 9: Authentication & Authorization Testing (ADR-002, Step 9)."""
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from app.authz.auth_session import AuthRoleSession
from app.authz.matrix_engine import AccessControlMatrixEngine
from app.schemas.enums import Severity, Confidence

FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "fixtures" / "authz-fixture"

def load_app_from_file(file_path: Path):
    spec = importlib.util.spec_from_file_location("module.name", file_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, "app")

insecure_app = load_app_from_file(FIXTURE_DIR / "insecure_app.py")
clean_app = load_app_from_file(FIXTURE_DIR / "clean_app.py")


def test_authz_matrix_detects_horizontal_idor_and_vertical_bfla():
    """
    Gate 9 Verification:
    Two-user fixture app with seeded IDOR + admin-route bug is detected:
    1. Horizontal Privilege Escalation (User A opens User B's document)
    2. Vertical Privilege Escalation (User A accesses Admin stats)
    3. Protected route open to anonymous users
    4. Plain language descriptions verified
    """
    client = TestClient(insecure_app)

    def client_fn(session: AuthRoleSession, method: str, url: str):
        headers = session.get_headers()
        path = url.replace("https://securescanbox.xyz", "")
        if method == "GET":
            resp = client.get(path, headers=headers)
        else:
            resp = client.post(path, headers=headers)
        return resp.status_code, resp.text, dict(resp.headers)

    matrix_engine = AccessControlMatrixEngine(base_url="https://securescanbox.xyz")

    routes = [
        {"method": "GET", "path": "/api/v1/profile"},
        {"method": "GET", "path": "/api/v1/documents/{id}", "user_b_object_id": "doc-user-b-1"},
        {"method": "GET", "path": "/api/v1/admin/stats"}
    ]

    findings, passes = matrix_engine.evaluate_matrix(routes, client_fn=client_fn)

    rule_ids = [f.rule_id for f in findings]

    # 1. Horizontal IDOR / Privilege Escalation
    assert "authz-horizontal-privilege-escalation" in rule_ids
    idor_finding = next(f for f in findings if f.rule_id == "authz-horizontal-privilege-escalation")
    assert idor_finding.severity == Severity.CRITICAL
    assert idor_finding.confidence == Confidence.CONFIRMED
    assert "User A could open User B's records" in idor_finding.description

    # 2. Vertical Privilege Escalation (BFLA)
    assert "authz-vertical-privilege-escalation" in rule_ids
    bfla_finding = next(f for f in findings if f.rule_id == "authz-vertical-privilege-escalation")
    assert bfla_finding.severity == Severity.CRITICAL
    assert "Regular User A could access administrative function" in bfla_finding.description

    # 3. Protected route open to anon
    assert "authz-protected-route-open-to-anon" in rule_ids
    anon_finding = next(f for f in findings if f.rule_id == "authz-protected-route-open-to-anon")
    assert "/api/v1/profile" in anon_finding.description


def test_authz_matrix_credential_absence_proof():
    """Gate 9 Verification: Proof of zero credential/token leakage in findings or descriptions."""
    matrix_engine = AccessControlMatrixEngine(
        base_url="https://securescanbox.xyz",
        user_a=AuthRoleSession("user_a", "BEARER", "super_secret_raw_token_a_12345"),
        user_b=AuthRoleSession("user_b", "BEARER", "super_secret_raw_token_b_67890"),
        admin=AuthRoleSession("admin", "BEARER", "super_secret_raw_token_admin_99999")
    )

    routes = [
        {"method": "GET", "path": "/api/v1/documents/{id}", "user_b_object_id": "doc-user-b-1", "user_a_on_b_status": 200},
        {"method": "GET", "path": "/api/v1/admin/stats", "user_a_admin_status": 200}
    ]

    findings, _ = matrix_engine.evaluate_matrix(routes)

    # Prove credentials are completely absent
    for f in findings:
        assert "super_secret_raw_token_a_12345" not in f.raw_snippet
        assert "super_secret_raw_token_a_12345" not in f.description
        assert "super_secret_raw_token_b_67890" not in f.raw_snippet
        assert "super_secret_raw_token_admin_99999" not in f.raw_snippet

    assert matrix_engine.zero_credentials_leaked is True


def test_authz_matrix_clean_app_produces_pass_evidenced():
    """Gate 9 Verification: Hardened application produces PASS_EVIDENCED and zero vulnerabilities."""
    client = TestClient(clean_app)

    def client_fn(session: AuthRoleSession, method: str, url: str):
        headers = session.get_headers()
        path = url.replace("https://securescanbox.xyz", "")
        if method == "GET":
            resp = client.get(path, headers=headers)
        else:
            resp = client.post(path, headers=headers)
        return resp.status_code, resp.text, dict(resp.headers)

    matrix_engine = AccessControlMatrixEngine(base_url="https://securescanbox.xyz")

    routes = [
        {"method": "GET", "path": "/api/v1/profile"},
        {"method": "GET", "path": "/api/v1/documents/{id}", "user_b_object_id": "doc-user-b-1"},
        {"method": "GET", "path": "/api/v1/admin/stats"}
    ]

    findings, passes = matrix_engine.evaluate_matrix(routes, client_fn=client_fn)

    # Zero vulnerability findings
    assert len(findings) == 0

    # Explicit PASS_EVIDENCED item
    pass_ids = [p.rule_id for p in passes]
    assert "pass-authz-access-matrix-enforced" in pass_ids
