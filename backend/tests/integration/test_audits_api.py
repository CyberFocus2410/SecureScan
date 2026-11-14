"""Integration tests for Audits & Repositories API endpoints."""
import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def mock_background_worker(monkeypatch):
    """
    Mock the async import worker pipeline so tests do not make real network calls
    or prematurely finish background tasks before dedupe/quota checks run.
    """
    monkeypatch.setattr("app.api.v1.audits.execute_import_pipeline", lambda audit_id: None)


def test_repository_lifecycle_and_canonicalization():
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}

    # 1. Create repository
    payload = {
        "github_url": "https://github.com/fastapi/fastapi.git",
        "branch": "master"
    }
    res = client.post("/api/v1/repositories", json=payload, headers=headers)
    assert res.status_code == 200
    repo_data = res.json()
    assert repo_data["github_owner"] == "fastapi"
    assert repo_data["github_repo"] == "fastapi"
    assert repo_data["canonical_url"] == "https://github.com/fastapi/fastapi"
    repo_id = repo_data["id"]

    # 2. Get repository by ID
    get_res = client.get(f"/api/v1/repositories/{repo_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == repo_id


def test_audit_submission_and_event_stream():
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}

    # 1. Register repo
    repo_res = client.post(
        "/api/v1/repositories",
        json={"github_url": "https://github.com/pallets/flask"},
        headers=headers
    )
    repo_id = repo_res.json()["id"]

    # 2. Start audit -> 202 Accepted
    audit_res = client.post(
        "/api/v1/audits",
        json={"repository_id": repo_id, "scopes": ["SECURITY", "DPDP"]},
        headers=headers
    )
    assert audit_res.status_code == 202
    audit_data = audit_res.json()
    audit_id = audit_data["audit_id"]
    assert audit_data["status"] == "QUEUED"
    assert "poll_url" in audit_data

    # 3. Get audit status
    status_res = client.get(f"/api/v1/audits/{audit_id}", headers=headers)
    assert status_res.status_code == 200
    assert status_res.json()["id"] == audit_id

    # 4. Get audit events stream
    events_res = client.get(f"/api/v1/audits/{audit_id}/events", headers=headers)
    assert events_res.status_code == 200
    events = events_res.json()
    assert len(events) >= 1
    assert events[0]["stage"] in ("QUEUED", "IMPORTING")


def test_audit_deduplication_409():
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}

    # Register repo
    repo_res = client.post(
        "/api/v1/repositories",
        json={"github_url": "https://github.com/django/django"},
        headers=headers
    )
    repo_id = repo_res.json()["id"]

    # Submit first audit
    first_res = client.post(
        "/api/v1/audits",
        json={"repository_id": repo_id, "scopes": ["SECURITY"]},
        headers=headers
    )
    assert first_res.status_code == 202

    # Submit second identical active audit in same session -> 409 Conflict
    dup_res = client.post(
        "/api/v1/audits",
        json={"repository_id": repo_id, "scopes": ["SECURITY"]},
        headers=headers
    )
    assert dup_res.status_code == 409
    err = dup_res.json()
    assert err["error"]["code"] == "ERR_DUPLICATE_ACTIVE_AUDIT"


def test_session_concurrency_quota_429():
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}

    # Register 3 different repositories
    repos = []
    for name in ["repo-a", "repo-b", "repo-c"]:
        r = client.post(
            "/api/v1/repositories",
            json={"github_url": f"https://github.com/org-{session_id[:6]}/{name}"},
            headers=headers
        )
        repos.append(r.json()["id"])

    # Launch audit 1 (Quota limit = 2)
    res1 = client.post("/api/v1/audits", json={"repository_id": repos[0]}, headers=headers)
    assert res1.status_code == 202

    # Launch audit 2
    res2 = client.post("/api/v1/audits", json={"repository_id": repos[1]}, headers=headers)
    assert res2.status_code == 202

    # Launch audit 3 -> Must trigger 429 Quota Exceeded!
    res3 = client.post("/api/v1/audits", json={"repository_id": repos[2]}, headers=headers)
    assert res3.status_code == 429
    err = res3.json()
    assert err["error"]["code"] == "ERR_QUOTA_EXCEEDED"


def test_at15_cross_session_isolation_403():
    """AT-15 (Access control portion): Cross-session audit access is denied."""
    session_a = str(uuid.uuid4())
    session_b = str(uuid.uuid4())

    # Session A creates repository and starts audit
    repo_res = client.post(
        "/api/v1/repositories",
        json={"github_url": f"https://github.com/private-corp/service-{session_a[:6]}"},
        headers={"X-Session-ID": session_a}
    )
    repo_id = repo_res.json()["id"]

    audit_res = client.post(
        "/api/v1/audits",
        json={"repository_id": repo_id},
        headers={"X-Session-ID": session_a}
    )
    audit_id = audit_res.json()["audit_id"]

    # Session B attempts to read Session A's audit -> 403 Forbidden!
    forbidden_res = client.get(
        f"/api/v1/audits/{audit_id}",
        headers={"X-Session-ID": session_b}
    )
    assert forbidden_res.status_code == 403
    err = forbidden_res.json()
    assert err["error"]["code"] == "ERR_UNAUTHORIZED_SESSION"

    # Session B attempts to read Session A's audit events -> 403 Forbidden!
    events_forbidden = client.get(
        f"/api/v1/audits/{audit_id}/events",
        headers={"X-Session-ID": session_b}
    )
    assert events_forbidden.status_code == 403
