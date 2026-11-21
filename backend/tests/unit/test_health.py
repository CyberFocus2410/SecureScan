"""Unit test for GET /api/v1/health endpoint."""
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OK"
    assert data["version"] == settings.VERSION
    assert data["as_of_date"] == settings.AS_OF_DATE
    assert "services" in data
    assert data["services"]["database"] == "CONNECTED"


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "SecureScan AI"
    assert data["health"] == "/api/v1/health"

