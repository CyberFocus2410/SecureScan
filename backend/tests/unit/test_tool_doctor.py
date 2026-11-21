"""Unit tests for tool doctor diagnostic reporting and admin endpoint."""
from fastapi.testclient import TestClient
from app.main import app
from app.services.tool_doctor import run_tool_diagnostics

client = TestClient(app)


def test_run_tool_diagnostics_coverage():
    """Verify tool doctor checks all 10 mandated areas with operational status."""
    report = run_tool_diagnostics()
    assert report["total_areas"] == 10
    assert report["status"] in ("HEALTHY", "DEGRADED")
    assert report["failed_count"] == 0
    assert len(report["tools"]) == 10

    categories = [t["category"] for t in report["tools"]]
    assert "SAST (Multi-language)" in categories
    assert "Deep SAST (Taint)" in categories
    assert "Secrets (Current Files)" in categories
    assert "Secrets (Git History)" in categories
    assert "Dependencies / SCA" in categories
    assert "SBOM Generation" in categories
    assert "Container / Dockerfile" in categories
    assert "Infrastructure as Code (IaC)" in categories
    assert "GitHub Actions" in categories
    assert "Frontend JS Libraries" in categories

    for tool in report["tools"]:
        assert tool["status"] in ("PASS", "FALLBACK_ACTIVE")
        assert tool["active_engine"] is not None


def test_admin_tools_api_endpoint():
    """Verify GET /api/v1/admin/tools returns 200 with valid structure."""
    response = client.get("/api/v1/admin/tools")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "tools" in data
    assert "sandbox" in data
    assert len(data["tools"]) == 10
