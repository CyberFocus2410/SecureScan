"""Integration tests for local repository archive (.zip) and folder upload scanning."""
import io
import shutil
import uuid
import zipfile
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.core.db import SessionLocal
from app.models.models import AuditModel, FindingModel
from app.workers.audit_worker import execute_scan_pipeline

client = TestClient(app)


def _make_zip_bytes(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return buf.getvalue()


def test_upload_zip_and_run_full_audit():
    """Verify .zip upload stages worktree, detects stack, runs scanners, and redacts secrets."""
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}

    zip_bytes = _make_zip_bytes({
        "my-fastapi-app/requirements.txt": "fastapi==0.115.0\nuvicorn==0.34.0\n",
        "my-fastapi-app/app.py": (
            "from fastapi import FastAPI\n"
            "import sqlite3\n"
            "app = FastAPI()\n"
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLEFAKETOKEN'\n"
            "@app.get('/users')\n"
            "def get_user(uid: str):\n"
            "    conn = sqlite3.connect('db.sqlite')\n"
            "    return conn.execute(f'SELECT * FROM users WHERE id={uid}').fetchall()\n"
        ),
    })

    res = client.post(
        "/api/v1/repositories/upload",
        files={"file": ("my-fastapi-app.zip", zip_bytes, "application/zip")},
        headers=headers,
    )
    assert res.status_code == 201, res.text
    repo_data = res.json()
    repo_id = repo_data["id"]

    try:
        assert repo_data["github_owner"] == "local-upload"
        assert repo_data["github_repo"] == "my-fastapi-app"
        assert repo_data["canonical_url"].startswith("upload://")
        assert repo_data["default_branch"] == "uploaded"
        assert len(repo_data["last_commit_sha"]) == 40
        assert "Python" in repo_data["detected_languages"]
        assert "FastAPI" in repo_data["detected_frameworks"]

        # Create audit and run worker directly without passing worktree_dir
        audit_res = client.post(
            "/api/v1/audits",
            json={"repository_id": repo_id, "scopes": ["SECURITY", "DPDP"]},
            headers=headers,
        )
        assert audit_res.status_code == 202, audit_res.text
        audit_id = audit_res.json()["audit_id"]

        execute_scan_pipeline(audit_id)

        db = SessionLocal()
        try:
            audit_db = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
            assert audit_db is not None
            assert audit_db.status in ("COMPLETED", "PARTIAL")

            findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
            assert len(findings) >= 1
            for f in findings:
                assert "AKIAIOSFODNN7EXAMPLEFAKETOKEN" not in (f.redacted_snippet or "")
                assert "AKIAIOSFODNN7EXAMPLEFAKETOKEN" not in (f.description or "")
        finally:
            db.close()
    finally:
        staged_dir = settings.WORKTREE_STORAGE_DIR / "uploads" / repo_id
        shutil.rmtree(staged_dir, ignore_errors=True)


def test_upload_folder_files():
    """Verify multi-file folder upload detects Node/Express and skips node_modules."""
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}

    res = client.post(
        "/api/v1/repositories/upload",
        files=[
            ("files", ("package.json", b'{"name": "demo", "dependencies": {"express": "^4.18.0"}}', "application/json")),
            ("files", ("index.js", b"const express = require('express'); const app = express();\n", "text/javascript")),
            ("files", ("bad.js", b"ignored", "text/javascript")),
        ],
        data={
            "relative_paths": [
                "demo-app/package.json",
                "demo-app/src/index.js",
                "demo-app/node_modules/pkg/bad.js",
            ]
        },
        headers=headers,
    )
    assert res.status_code == 201, res.text
    repo_data = res.json()
    try:
        assert repo_data["github_repo"] == "demo-app"
        assert "JavaScript" in repo_data["detected_languages"]
        assert "Express" in repo_data["detected_frameworks"]
    finally:
        shutil.rmtree(settings.WORKTREE_STORAGE_DIR / "uploads" / repo_data["id"], ignore_errors=True)


def test_upload_rejects_zip_slip_traversal():
    """Verify path traversal entries inside .zip are rejected with HTTP 400."""
    session_id = str(uuid.uuid4())
    zip_bytes = _make_zip_bytes({"../../evil.py": "print('pwned')"})

    res = client.post(
        "/api/v1/repositories/upload",
        files={"file": ("evil.zip", zip_bytes, "application/zip")},
        headers={"X-Session-ID": session_id},
    )
    assert res.status_code == 400


def test_upload_rejects_non_zip_archive():
    """Verify non-.zip single file uploads are rejected with HTTP 400."""
    session_id = str(uuid.uuid4())
    res = client.post(
        "/api/v1/repositories/upload",
        files={"file": ("code.txt", b"hello world", "text/plain")},
        headers={"X-Session-ID": session_id},
    )
    assert res.status_code == 400
