"""Additive migration: targets, scopes, verifications, consent, findings extensions (Step 3, ADR-002)

Revision ID: 003_add_unified_findings_and_targets
Revises: 002_add_tool_runs_table
Create Date: 2026-11-20 23:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '003_add_unified_findings_and_targets'
down_revision: Union[str, None] = '002_add_tool_runs_table'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. targets table
    op.create_table(
        'targets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('target_type', sa.String(length=20), nullable=False),
        sa.Column('url', sa.String(length=512), nullable=False),
        sa.Column('verified', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_targets_session_id', 'targets', ['session_id'])
    op.create_index('ix_targets_url', 'targets', ['url'])

    # 2. Add target_id to audits table
    with op.batch_alter_table('audits') as batch_op:
        batch_op.add_column(sa.Column('target_id', sa.String(length=36), nullable=True))
        batch_op.create_index('ix_audits_target_id', ['target_id'])

    # 3. target_verifications table
    op.create_table(
        'target_verifications',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column('verification_method', sa.String(length=30), nullable=False),
        sa.Column('token', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='PENDING'),
        sa.Column('proof_details', sa.JSON(), nullable=True),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_target_verifications_target_id', 'target_verifications', ['target_id'])

    # 4. scan_profiles table
    op.create_table(
        'scan_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('intensity', sa.String(length=20), nullable=False, server_default='STANDARD'),
        sa.Column('max_rps', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('max_requests', sa.Integer(), nullable=False, server_default='500'),
        sa.Column('max_duration_seconds', sa.Integer(), nullable=False, server_default='1200'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # 5. scan_scopes table
    op.create_table(
        'scan_scopes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column('allowed_hosts', sa.JSON(), nullable=False),
        sa.Column('allowed_paths', sa.JSON(), nullable=False),
        sa.Column('excluded_paths', sa.JSON(), nullable=False),
        sa.Column('max_rps', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('max_crawl_depth', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_scopes_target_id', 'scan_scopes', ['target_id'])

    # 6. consent_records table
    op.create_table(
        'consent_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=64), nullable=False),
        sa.Column('client_ip', sa.String(length=64), nullable=False),
        sa.Column('terms_version', sa.String(length=20), nullable=False, server_default='2.0'),
        sa.Column('scope_hash', sa.String(length=64), nullable=False),
        sa.Column('accepted_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_consent_records_target_id', 'consent_records', ['target_id'])
    op.create_index('ix_consent_records_user_id', 'consent_records', ['user_id'])

    # 7. test_accounts table
    op.create_table(
        'test_accounts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('auth_type', sa.String(length=30), nullable=False, server_default='BEARER'),
        sa.Column('encrypted_credentials', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_test_accounts_target_id', 'test_accounts', ['target_id'])

    # 8. assets table
    op.create_table(
        'assets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column('asset_type', sa.String(length=50), nullable=False),
        sa.Column('value', sa.String(length=512), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_assets_target_id', 'assets', ['target_id'])

    # 9. endpoints table
    op.create_table(
        'endpoints',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('path', sa.String(length=1024), nullable=False),
        sa.Column('auth_required', sa.String(length=20), nullable=False, server_default='UNKNOWN'),
        sa.Column('discovered_via', sa.String(length=50), nullable=False, server_default='SOURCE'),
        sa.Column('pii_fields', sa.JSON(), nullable=True),
        sa.Column('rate_limited', sa.String(length=20), nullable=True, server_default='UNKNOWN'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_endpoints_target_id', 'endpoints', ['target_id'])

    # 10. sbom_components table
    op.create_table(
        'sbom_components',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=100), nullable=False),
        sa.Column('ecosystem', sa.String(length=50), nullable=False),
        sa.Column('purl', sa.String(length=512), nullable=True),
        sa.Column('license', sa.String(length=100), nullable=True),
        sa.Column('is_direct', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('vulnerabilities_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_sbom_components_audit_id', 'sbom_components', ['audit_id'])

    # 11. scan_comparisons table
    op.create_table(
        'scan_comparisons',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('base_audit_id', sa.String(length=36), nullable=False),
        sa.Column('target_audit_id', sa.String(length=36), nullable=False),
        sa.Column('new_findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('fixed_findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('recurrent_findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('comparison_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['base_audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_comparisons_base_audit_id', 'scan_comparisons', ['base_audit_id'])
    op.create_index('ix_scan_comparisons_target_audit_id', 'scan_comparisons', ['target_audit_id'])

    # 12. Additive extensions to findings table
    with op.batch_alter_table('findings') as batch_op:
        batch_op.add_column(sa.Column('engine', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('tool', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('tool_version', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('verified_state', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('exploitability', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('exposure', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('data_sensitivity', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('source', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('data_flow', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('sink', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('affected', sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column('request_evidence', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('response_evidence', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('standards', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('priority', sa.String(length=10), nullable=True))
        batch_op.add_column(sa.Column('plain_title', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('plain_summary', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('why_it_matters', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('how_to_fix', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('how_to_verify_fix', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('fix_effort', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('fix_prompt', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('related_finding_ids', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('attack_chain_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('first_seen_scan_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('status', sa.String(length=30), nullable=False, server_default='open'))
        batch_op.add_column(sa.Column('signals', sa.JSON(), nullable=True))


def downgrade() -> None:
    # 1. Remove finding columns
    with op.batch_alter_table('findings') as batch_op:
        batch_op.drop_column('signals')
        batch_op.drop_column('status')
        batch_op.drop_column('first_seen_scan_id')
        batch_op.drop_column('attack_chain_id')
        batch_op.drop_column('related_finding_ids')
        batch_op.drop_column('fix_prompt')
        batch_op.drop_column('fix_effort')
        batch_op.drop_column('how_to_verify_fix')
        batch_op.drop_column('how_to_fix')
        batch_op.drop_column('why_it_matters')
        batch_op.drop_column('plain_summary')
        batch_op.drop_column('plain_title')
        batch_op.drop_column('priority')
        batch_op.drop_column('standards')
        batch_op.drop_column('response_evidence')
        batch_op.drop_column('request_evidence')
        batch_op.drop_column('affected')
        batch_op.drop_column('sink')
        batch_op.drop_column('data_flow')
        batch_op.drop_column('source')
        batch_op.drop_column('data_sensitivity')
        batch_op.drop_column('exposure')
        batch_op.drop_column('exploitability')
        batch_op.drop_column('verified_state')
        batch_op.drop_column('tool_version')
        batch_op.drop_column('tool')
        batch_op.drop_column('engine')

    op.drop_table('scan_comparisons')
    op.drop_table('sbom_components')
    op.drop_table('endpoints')
    op.drop_table('assets')
    op.drop_table('test_accounts')
    op.drop_table('consent_records')
    op.drop_table('scan_scopes')
    op.drop_table('scan_profiles')
    op.drop_table('target_verifications')

    with op.batch_alter_table('audits') as batch_op:
        batch_op.drop_index('ix_audits_target_id')
        batch_op.drop_column('target_id')

    op.drop_table('targets')
