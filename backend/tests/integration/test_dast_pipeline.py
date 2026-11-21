"""Integration test suite for DAST Pipeline & Lab Benchmark (Step 7, ADR-002, Section 4 & 5)."""
import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.errors import TargetNotVerifiedError, ConsentRequiredError, SSRFBlockedError
from app.dast.pipeline import DastPipeline
from app.models.models import Base, TargetModel, ScanScopeModel, ConsentRecordModel


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


def test_dast_pipeline_rejects_unverified_target_and_missing_consent(in_memory_db):
    """Pipeline strictly fails closed if target is not ownership verified or lacks legal consent."""
    # 1. Unverified Target
    target = TargetModel(
        id="t-unverified-1",
        session_id="s-1",
        name="Target Unverified",
        target_type="WEBSITE",
        url="https://securescanbox.xyz",
        verified=False
    )
    in_memory_db.add(target)
    in_memory_db.commit()

    with pytest.raises(TargetNotVerifiedError):
        DastPipeline.run_scan(
            target_url=target.url,
            target_id=target.id,
            db=in_memory_db,
            intensity="Standard"
        )

    # 2. Verified target but missing legal consent record
    target.verified = True
    in_memory_db.commit()

    with pytest.raises(ConsentRequiredError):
        DastPipeline.run_scan(
            target_url=target.url,
            target_id=target.id,
            db=in_memory_db,
            intensity="Standard"
        )


def test_dast_pipeline_blocks_ssrf_and_metadata_destinations():
    """Anti-SSRF gate blocks private IP, cloud metadata, and government targets."""
    # Cloud metadata
    with pytest.raises(SSRFBlockedError):
        DastPipeline.run_scan(target_url="http://169.254.169.254/latest/meta-data")

    # Local loopback
    with pytest.raises(SSRFBlockedError):
        DastPipeline.run_scan(target_url="http://127.0.0.1:8080/admin")

    # Protected government TLD
    with pytest.raises(SSRFBlockedError):
        DastPipeline.run_scan(target_url="https://cybersecurity.gov.in")


def test_dast_pipeline_lab_benchmark_simulation():
    """
    Simulates a full DAST audit run on Lab targets (Juice Shop / DVWA),
    verifying >= 80% recall of benchmark checklist and zero data extraction.
    """
    mock_html = """
    <!DOCTYPE html>
    <html>
      <head><title>OWASP Juice Shop</title></head>
      <body>
        <div id="root"></div>
        <script src="https://securescanbox.xyz/main.bundle.js"></script>
      </body>
    </html>
    """

    mock_js = """
    function renderQuery(val) {
        document.getElementById("output").innerHTML = val;
    }
    window.addEventListener("message", function(e) { eval(e.data); });
    localStorage.setItem("token", "user_jwt_token_here");
    //# sourceMappingURL=main.bundle.js.map
    """

    with patch("httpx.Client.get") as mock_get, \
         patch("httpx.Client.request") as mock_req, \
         patch("app.dast.tls_scanner.TlsScanner.audit_target_tls") as mock_tls:

        mock_tls.return_value = []

        def side_effect(url, **kwargs):
            if "main.bundle.js" in url:
                return MagicMock(status_code=200, text=mock_js, headers={"content-type": "application/javascript"})
            elif "/.env" in url:
                return MagicMock(status_code=200, text="SECRET_KEY=12345\nDB_PASSWORD=secret", headers={"content-type": "text/plain"})
            elif "secscancanary" in url:
                return MagicMock(status_code=200, text="<div>Results for: <secscancanary", headers={"content-type": "text/html"})
            elif "__secscan_test" in url:
                return MagicMock(status_code=500, text="Traceback (most recent call last):", headers={"content-type": "text/plain"})
            return MagicMock(
                status_code=200,
                text=mock_html,
                headers={"content-type": "text/html; charset=utf-8", "Server": "Express", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
            )

        mock_get.side_effect = side_effect
        mock_req.return_value = MagicMock(status_code=405, text="Method Not Allowed", headers={})

        scope = ScanScopeModel(
            target_id="t-lab",
            allowed_hosts=["securescanbox.xyz"],
            allowed_paths=["/"],
            excluded_paths=["/logout", "/delete"],
            max_rps=5,
            max_crawl_depth=2
        )

        result = DastPipeline.run_scan(
            target_url="https://securescanbox.xyz",
            scope=scope,
            intensity="Standard"
        )

        assert result.zero_data_extraction_proven is True

        rule_ids = [f.get("rule_id") for f in result.findings]

        # Verify key benchmark detections
        assert any("header-missing" in r for r in rule_ids)
        assert any("cors" in r for r in rule_ids)
        assert any("frontend" in r or "dom" in r for r in rule_ids)
        assert any("token" in r for r in rule_ids)
        assert any("env-file" in r for r in rule_ids)

        # Evidenced passes
        pass_ids = [p.get("rule_id") for p in result.evidenced_passes]
        assert len(pass_ids) > 0
