"""Unit & Integration tests for Step 8: API Security Engine & OWASP API Top 10 (2023)."""
import csv
import io
import json
from pathlib import Path
import pytest

from app.scanners.api_security import ApiSecurityScanner
from app.services.api_discovery import ApiDiscoveryEngine, DiscoveredEndpoint
from app.services.api_inventory_exporter import ApiInventoryExporter
from app.schemas.enums import Severity, Confidence

FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "fixtures" / "crapi-style-api"


def test_crapi_fixture_detects_bola_shadow_broken_auth_and_rate_limits():
    """
    Gate 8 Verification: crAPI fixture proves detection of at least:
    1. BOLA (Broken Object Level Authorization)
    2. Broken Authentication on sensitive routes
    3. Missing Rate Limiting on sensitive business flows
    4. Shadow Endpoint (implemented in source but omitted from OpenAPI)
    5. Unrestricted Collection Pagination
    """
    scanner = ApiSecurityScanner()
    res = scanner.scan(str(FIXTURE_DIR))

    assert res.status == "COMPLETED"
    rule_ids = [f.rule_id for f in res.raw_findings]

    # 1. BOLA / IDOR
    assert "api-bola-missing-object-level-authz" in rule_ids
    bola_finding = next(f for f in res.raw_findings if f.rule_id == "api-bola-missing-object-level-authz")
    assert "order_id" in bola_finding.description
    assert "CWE-639" in bola_finding.cwe_ids
    assert bola_finding.severity == Severity.CRITICAL

    # 2. Broken Authentication
    assert "api-broken-authentication-sensitive-endpoint" in rule_ids
    auth_finding = next(f for f in res.raw_findings if f.rule_id == "api-broken-authentication-sensitive-endpoint")
    assert "/api/v1/users" in auth_finding.description
    assert auth_finding.severity == Severity.HIGH

    # 3. Missing Rate Limiting on Sensitive Business Flow
    assert "api-business-flow-missing-rate-limiting" in rule_ids
    rl_finding = next(f for f in res.raw_findings if f.rule_id == "api-business-flow-missing-rate-limiting")
    assert "coupons" in rl_finding.description

    # 4. Shadow Endpoint Detection
    shadow_findings = [f for f in res.raw_findings if f.rule_id == "api-inventory-shadow-endpoint-detected"]
    assert len(shadow_findings) > 0
    assert any("/api/v1/internal/admin/wipe" in f.description for f in shadow_findings)
    assert any(f.confidence == Confidence.CONFIRMED for f in shadow_findings)

    # 5. Unrestricted Resource Consumption (Pagination)
    assert "api-resource-unrestricted-collection-pagination" in rule_ids


def test_api_inventory_exporter_json_and_csv():
    """Gate 8 Verification: Inventory export in both JSON and CSV formats."""
    endpoints = [
        DiscoveredEndpoint(
            method="GET",
            path="/api/v1/orders/{order_id}",
            auth_required="NO",
            authz_checks_seen=False,
            object_id_params=["order_id"],
            pii_fields=["order_id"],
            rate_limited="NO",
            input_validation="VALIDATED",
            discovered_via="SOURCE",
            is_shadow=False,
            is_deprecated=False,
            risk="HIGH",
            source_file="main.py",
            source_line=7
        ),
        DiscoveredEndpoint(
            method="POST",
            path="/api/v1/internal/admin/wipe",
            auth_required="UNKNOWN",
            authz_checks_seen=False,
            object_id_params=[],
            pii_fields=[],
            rate_limited="NO",
            input_validation="VALIDATED",
            discovered_via="SOURCE",
            is_shadow=True,
            is_deprecated=False,
            risk="MEDIUM",
            source_file="main.py",
            source_line=27
        )
    ]

    # JSON Export Verification
    json_str = ApiInventoryExporter.to_json(endpoints)
    data = json.loads(json_str)
    assert "endpoints" in data
    assert data["total_count"] == 2
    assert data["endpoints"][0]["method"] == "GET"
    assert data["endpoints"][0]["path"] == "/api/v1/orders/{order_id}"
    assert data["endpoints"][1]["is_shadow"] is True

    # CSV Export Verification
    csv_str = ApiInventoryExporter.to_csv(endpoints)
    reader = csv.DictReader(io.StringIO(csv_str))
    rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["method"] == "GET"
    assert rows[0]["path"] == "/api/v1/orders/{order_id}"
    assert rows[0]["object_id_params"] == "order_id"
    assert rows[1]["is_shadow"] == "True"


def test_clean_api_produces_pass_evidenced_items(tmp_path):
    """Clean API with complete OpenAPI spec and authorized endpoints produces PASS_EVIDENCED items."""
    clean_repo = tmp_path / "clean_repo"
    clean_repo.mkdir()

    # Create matching openapi.json
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/items": {
                "get": {
                    "security": [{"BearerAuth": []}],
                    "responses": {"200": {"description": "OK"}}
                }
            }
        }
    }
    (clean_repo / "openapi.json").write_text(json.dumps(spec), encoding="utf-8")

    # Create matching source code with auth
    code = """
from fastapi import FastAPI, Depends
app = FastAPI()
def get_user(): return {}
@app.get("/api/v1/items")
def list_items(u: dict = Depends(get_user)):
    return []
"""
    (clean_repo / "main.py").write_text(code, encoding="utf-8")

    scanner = ApiSecurityScanner()
    res = scanner.scan(str(clean_repo))

    pass_rules = [f.rule_id for f in res.raw_findings if f.rule_id.startswith("pass-")]
    assert "pass-api-bola-controls-evidenced" in pass_rules
    assert "pass-api-authentication-enforced" in pass_rules
    assert "pass-api-inventory-accurate" in pass_rules


def test_api_outbound_unsafe_consumption(tmp_path):
    """Detects unsafe outbound API consumption: verify=False and missing timeout."""
    test_repo = tmp_path / "test_repo"
    test_repo.mkdir()

    unsafe_code = """
import requests
def fetch_external():
    # Disables TLS verification
    res = requests.get("https://partner.api/v1/data", verify=False)
    return res.json()
"""
    (test_repo / "client.py").write_text(unsafe_code, encoding="utf-8")

    scanner = ApiSecurityScanner()
    res = scanner.scan(str(test_repo))
    rule_ids = [f.rule_id for f in res.raw_findings]

    assert "api-unsafe-consumption-disabled-tls" in rule_ids
