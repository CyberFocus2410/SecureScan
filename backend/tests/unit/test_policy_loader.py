"""Unit tests for policy loader: valid bundle parsing and error handling."""
import tempfile
from pathlib import Path
import pytest
from app.services.policy_loader import load_and_validate_policies
from app.core.errors import PolicyLoadError


def test_load_and_validate_policies_from_repo():
    bundle = load_and_validate_policies()
    assert bundle.security_controls.version == "1.0.0"
    assert len(bundle.security_controls.controls) >= 5
    assert bundle.dpdp_commencement.version == "1.0.0"
    assert len(bundle.dpdp_commencement.phases) >= 3
    assert bundle.penalty_schedule.version == "1.0.0"
    assert len(bundle.penalty_schedule.items) == 7


def test_policy_loader_rejects_missing_directory():
    with pytest.raises(PolicyLoadError):
        load_and_validate_policies(Path("/non/existent/path"))


def test_policy_loader_rejects_malformed_yaml(tmp_path: Path):
    # Create invalid YAML
    bad_file = tmp_path / "security_controls.yaml"
    bad_file.write_text("invalid_yaml: [unclosed list", encoding="utf-8")

    with pytest.raises(PolicyLoadError, match="YAML parsing syntax error|Policy file not found"):
        load_and_validate_policies(tmp_path)


def test_policy_loader_rejects_schema_mismatch(tmp_path: Path):
    # Valid YAML syntax but missing required fields
    bad_file = tmp_path / "security_controls.yaml"
    bad_file.write_text("version: '1.0'\ncontrols: [{'id': 123}]", encoding="utf-8")

    with pytest.raises(PolicyLoadError):
        load_and_validate_policies(tmp_path)

