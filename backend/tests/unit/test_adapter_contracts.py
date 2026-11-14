"""Unit tests for scanner adapter contracts."""
import uuid
from pathlib import Path
from app.scanners.gitleaks import GitleaksAdapter
from app.scanners.semgrep import SemgrepAdapter
from app.scanners.osv import OsvScannerAdapter
from app.scanners.bandit import BanditAdapter


def test_gitleaks_adapter_contract(tmp_path: Path):
    adapter = GitleaksAdapter()
    meta = adapter.metadata()
    assert meta.name.value == "gitleaks"
    assert meta.version == "8.21.2"
    assert adapter.supports(["Python"], ["FastAPI"]) is True

    test_file = tmp_path / "creds.py"
    test_file.write_text("API_KEY = 'AKIAIOSFODNN7EXAMPLEFAKETOKEN'", encoding="utf-8")

    ctx = adapter.prepare(tmp_path)
    res = adapter.execute(tmp_path, ctx)
    assert res.status == "COMPLETED"
    assert len(res.raw_findings) >= 1

    # Verify normalize scrubbed secrets
    norm = adapter.normalize(res.raw_findings, str(uuid.uuid4()))
    assert len(norm) >= 1
    assert "AKIAIOSFODNN7EXAMPLEFAKETOKEN" not in norm[0].redacted_snippet


def test_semgrep_adapter_contract(tmp_path: Path):
    adapter = SemgrepAdapter()
    meta = adapter.metadata()
    assert meta.name.value == "semgrep"
    assert meta.version == "1.102.0"
    assert adapter.supports(["Python"], []) is True
    assert adapter.supports(["Go"], []) is False

    vuln_file = tmp_path / "query.py"
    vuln_file.write_text("query = f'SELECT * FROM users WHERE id = {user_id}'", encoding="utf-8")

    ctx = adapter.prepare(tmp_path)
    res = adapter.execute(tmp_path, ctx)
    assert res.status == "COMPLETED"
    assert len(res.raw_findings) >= 1


def test_osv_adapter_contract(tmp_path: Path):
    adapter = OsvScannerAdapter()
    meta = adapter.metadata()
    assert meta.name.value == "osv-scanner"
    assert meta.version == "1.9.2"
    assert adapter.supports(["Python"], []) is True


def test_bandit_adapter_contract(tmp_path: Path):
    adapter = BanditAdapter()
    meta = adapter.metadata()
    assert meta.name.value == "bandit"
    assert meta.version == "1.8.0"
    assert adapter.supports(["Python"], []) is True
    assert adapter.supports(["Ruby"], []) is False

