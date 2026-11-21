"""Integration tests for Targets, Verification, Scope, and Consent API endpoints (Step 3)."""
import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_target_lifecycle_api():
    """Test full target registration, challenge creation, verification, scope, and consent flow."""
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}

    # 1. Register target
    res = client.post(
        "/api/v1/targets",
        json={"url": "https://api.myapp.test", "target_type": "API", "name": "MyApp API"},
        headers=headers
    )
    assert res.status_code == 201
    target = res.json()
    assert target["url"] == "https://api.myapp.test"
    assert target["verified"] is False
    target_id = target["id"]

    # 2. List targets for session
    list_res = client.get("/api/v1/targets", headers=headers)
    assert list_res.status_code == 200
    targets = list_res.json()
    assert any(t["id"] == target_id for t in targets)

    # 3. Create verification challenge
    chal_res = client.post(
        f"/api/v1/targets/{target_id}/challenges",
        json={"method": "DNS_TXT"},
        headers=headers
    )
    assert chal_res.status_code == 201
    challenge = chal_res.json()
    assert challenge["verification_method"] == "DNS_TXT"
    assert "token" in challenge
    token = challenge["token"]

    # 4. Attempt verification with invalid proof
    fail_res = client.post(
        f"/api/v1/targets/{target_id}/verify",
        json={"verification_id": challenge["id"], "proof": {"token": "wrong-token"}},
        headers=headers
    )
    assert fail_res.status_code == 200
    assert fail_res.json()["verified"] is False

    # 5. Successfully verify with mock token proof
    verify_res = client.post(
        f"/api/v1/targets/{target_id}/verify",
        json={"verification_id": challenge["id"], "proof": {"token": token}},
        headers=headers
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["verified"] is True

    # Check target is now marked verified
    get_target = client.get(f"/api/v1/targets/{target_id}", headers=headers)
    assert get_target.status_code == 200
    assert get_target.json()["verified"] is True

    # 6. Configure scope
    scope_res = client.post(
        f"/api/v1/targets/{target_id}/scope",
        json={
            "allowed_hosts": ["api.myapp.test"],
            "allowed_paths": ["/api/v1"],
            "excluded_paths": ["/api/v1/delete"],
            "max_rps": 10
        },
        headers=headers
    )
    assert scope_res.status_code == 200
    scope_data = scope_res.json()
    assert scope_data["max_rps"] == 10
    assert "/api/v1/delete" in scope_data["excluded_paths"]

    # 7. Record consent
    consent_res = client.post(
        f"/api/v1/targets/{target_id}/consent",
        json={"user_id": "auditor@myapp.test", "terms_version": "2.0"},
        headers=headers
    )
    assert consent_res.status_code == 201
    consent_data = consent_res.json()
    assert consent_data["user_id"] == "auditor@myapp.test"


def test_target_ssrf_blocking_via_api():
    """Verify that private IP and government domains are rejected via API."""
    headers = {"X-Session-ID": str(uuid.uuid4())}

    # Government domain
    res = client.post(
        "/api/v1/targets",
        json={"url": "https://service.gov.in"},
        headers=headers
    )
    assert res.status_code in [400, 422, 403]

    # Cloud metadata
    res_meta = client.post(
        "/api/v1/targets",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
        headers=headers
    )
    assert res_meta.status_code in [400, 422, 403]


def test_target_idor_cross_session_protection():
    """Verify cross-session access to another user's target is rejected with 403."""
    session_owner = str(uuid.uuid4())
    session_attacker = str(uuid.uuid4())

    # Owner creates target
    res = client.post(
        "/api/v1/targets",
        json={"url": "https://secure-target.example.org"},
        headers={"X-Session-ID": session_owner}
    )
    assert res.status_code == 201
    target_id = res.json()["id"]

    # Attacker tries to view target
    res_get = client.get(
        f"/api/v1/targets/{target_id}",
        headers={"X-Session-ID": session_attacker}
    )
    assert res_get.status_code == 403

    # Attacker tries to request challenge
    res_chal = client.post(
        f"/api/v1/targets/{target_id}/challenges",
        json={"method": "DNS_TXT"},
        headers={"X-Session-ID": session_attacker}
    )
    assert res_chal.status_code == 403
