"""Initial migration creating all Architecture §6 tables

Revision ID: 001_initial_tables
Revises: None
Create Date: 2026-11-14 12:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial_tables'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. repositories
    op.create_table(
        'repositories',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('github_owner', sa.String(length=255), nullable=False),
        sa.Column('github_repo', sa.String(length=255), nullable=False),
        sa.Column('canonical_url', sa.String(length=512), nullable=False),
        sa.Column('default_branch', sa.String(length=100), nullable=False),
        sa.Column('last_commit_sha', sa.String(length=40), nullable=True),
        sa.Column('detected_languages', sa.JSON(), nullable=True),
        sa.Column('detected_frameworks', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('canonical_url')
    )
    op.create_index('ix_repositories_canonical_url', 'repositories', ['canonical_url'])

    # 2. audits
    op.create_table(
        'audits',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('repository_id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=64), nullable=False),
        sa.Column('commit_sha', sa.String(length=40), nullable=True),
        sa.Column('scopes', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('current_stage', sa.String(length=50), nullable=False),
        sa.Column('coverage_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audits_repository_id', 'audits', ['repository_id'])
    op.create_index('ix_audits_session_id', 'audits', ['session_id'])
    op.create_index('ix_audits_status', 'audits', ['status'])

    # 3. scanner_runs
    op.create_table(
        'scanner_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('scanner', sa.String(length=50), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('findings_count', sa.Integer(), nullable=True),
        sa.Column('error_code', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scanner_runs_audit_id', 'scanner_runs', ['audit_id'])

    # 4. findings
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('scanner_name', sa.String(length=50), nullable=False),
        sa.Column('scanner_version', sa.String(length=50), nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('confidence', sa.String(length=20), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('file_path', sa.String(length=1024), nullable=False),
        sa.Column('start_line', sa.Integer(), nullable=False),
        sa.Column('end_line', sa.Integer(), nullable=False),
        sa.Column('cwe_ids', sa.JSON(), nullable=True),
        sa.Column('owasp_refs', sa.JSON(), nullable=True),
        sa.Column('redacted_snippet', sa.Text(), nullable=True),
        sa.Column('technical_fix', sa.Text(), nullable=True),
        sa.Column('validation_steps', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_findings_audit_id', 'findings', ['audit_id'])
    op.create_index('ix_findings_fingerprint', 'findings', ['fingerprint'])

    # 5. control_results
    op.create_table(
        'control_results',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('control_id', sa.String(length=50), nullable=False),
        sa.Column('domain', sa.String(length=20), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('state', sa.String(length=30), nullable=False),
        sa.Column('readiness_label', sa.String(length=50), nullable=True),
        sa.Column('effective_date_status', sa.String(length=30), nullable=True),
        sa.Column('effective_date', sa.Date(), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('evidence_tier', sa.String(length=30), nullable=True),
        sa.Column('evaluated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_control_results_audit_id', 'control_results', ['audit_id'])
    op.create_index('ix_control_results_control_id', 'control_results', ['control_id'])

    # 6. evidence
    op.create_table(
        'evidence',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=True),
        sa.Column('control_result_id', sa.String(length=36), nullable=True),
        sa.Column('tier', sa.String(length=30), nullable=False),
        sa.Column('path', sa.String(length=1024), nullable=False),
        sa.Column('start_line', sa.Integer(), nullable=True),
        sa.Column('end_line', sa.Integer(), nullable=True),
        sa.Column('redacted_excerpt', sa.Text(), nullable=False),
        sa.Column('raw_data', sa.JSON(), nullable=True),
        sa.Column('provenance', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['control_result_id'], ['control_results.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_evidence_audit_id', 'evidence', ['audit_id'])

    # 7. control_catalogue
    op.create_table(
        'control_catalogue',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('control_id', sa.String(length=50), nullable=False),
        sa.Column('domain', sa.String(length=20), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=False),
        sa.Column('label', sa.String(length=255), nullable=False),
        sa.Column('source_uri', sa.String(length=512), nullable=True),
        sa.Column('source_ref', sa.String(length=100), nullable=True),
        sa.Column('applicability_json', sa.JSON(), nullable=True),
        sa.Column('effective_at', sa.Date(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('control_id')
    )

    # 8. owasp_mappings
    op.create_table(
        'owasp_mappings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('internal_control_id', sa.String(length=50), nullable=False),
        sa.Column('standard', sa.String(length=50), nullable=False),
        sa.Column('standard_version', sa.String(length=20), nullable=False),
        sa.Column('external_ref', sa.String(length=50), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_owasp_mappings_control', 'owasp_mappings', ['internal_control_id'])

    # 9. dpdp_profiles
    op.create_table(
        'dpdp_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('questionnaire_json', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('audit_id')
    )

    # 10. legal_sources
    op.create_table(
        'legal_sources',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('doc_name', sa.String(length=255), nullable=False),
        sa.Column('clause_ref', sa.String(length=100), nullable=False),
        sa.Column('source_url', sa.String(length=512), nullable=True),
        sa.Column('gazette_id', sa.String(length=50), nullable=True),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('effective_at', sa.Date(), nullable=True),
        sa.Column('reviewed_at', sa.Date(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # 11. penalty_categories
    op.create_table(
        'penalty_categories',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('schedule_item', sa.Integer(), nullable=False),
        sa.Column('related_act_section', sa.String(length=100), nullable=False),
        sa.Column('ceiling_inr', sa.String(length=50), nullable=False),
        sa.Column('legal_source_id', sa.String(length=36), nullable=True),
        sa.Column('caveat', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['legal_source_id'], ['legal_sources.id']),
        sa.PrimaryKeyConstraint('id')
    )

    # 12. remediation_actions
    op.create_table(
        'remediation_actions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('priority', sa.String(length=10), nullable=False),
        sa.Column('action_type', sa.String(length=30), nullable=False),
        sa.Column('target_id', sa.String(length=100), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('steps_json', sa.JSON(), nullable=False),
        sa.Column('validation_method', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_remediation_actions_audit_id', 'remediation_actions', ['audit_id'])

    # 13. report_artifacts
    op.create_table(
        'report_artifacts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('format', sa.String(length=10), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('safe_storage_key', sa.String(length=512), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_report_artifacts_audit_id', 'report_artifacts', ['audit_id'])

    # 14. audit_events
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('stage', sa.String(length=50), nullable=False),
        sa.Column('state', sa.String(length=20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_events_audit_id', 'audit_events', ['audit_id'])


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_table('report_artifacts')
    op.drop_table('remediation_actions')
    op.drop_table('penalty_categories')
    op.drop_table('legal_sources')
    op.drop_table('dpdp_profiles')
    op.drop_table('owasp_mappings')
    op.drop_table('control_catalogue')
    op.drop_table('evidence')
    op.drop_table('control_results')
    op.drop_table('findings')
    op.drop_table('scanner_runs')
    op.drop_table('audits')
    op.drop_table('repositories')

