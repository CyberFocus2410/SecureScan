"""Unit tests verifying database schema and migration integrity."""
from sqlalchemy import inspect
from app.core.db import engine, Base
import app.models  # ensure models registered


def test_database_tables_exist():
    # Verify all 14 required tables exist in metadata and DB
    expected_tables = {
        "repositories",
        "audits",
        "scanner_runs",
        "findings",
        "control_results",
        "evidence",
        "control_catalogue",
        "owasp_mappings",
        "dpdp_profiles",
        "legal_sources",
        "penalty_categories",
        "remediation_actions",
        "report_artifacts",
        "audit_events"
    }
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    for t in expected_tables:
        assert t in table_names, f"Expected table '{t}' missing from database schema!"


def test_repository_table_columns():
    inspector = inspect(engine)
    columns = {col["name"] for col in inspector.get_columns("repositories")}
    expected_cols = {"id", "github_owner", "github_repo", "canonical_url", "default_branch", "created_at"}
    assert expected_cols.issubset(columns)

