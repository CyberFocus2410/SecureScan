"""Additive migration creating tool_runs table (Step 2, ADR-002)

Revision ID: 002_add_tool_runs_table
Revises: 001_initial_tables
Create Date: 2026-11-20 12:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '002_add_tool_runs_table'
down_revision: Union[str, None] = '001_initial_tables'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'tool_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('audit_id', sa.String(length=36), nullable=False),
        sa.Column('tool', sa.String(length=50), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('exit_status', sa.String(length=30), nullable=False),
        sa.Column('duration_ms', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('coverage_metrics', sa.JSON(), nullable=True),
        sa.Column('stdout_preview', sa.Text(), nullable=True),
        sa.Column('stderr_preview', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_tool_runs_audit_id', 'tool_runs', ['audit_id'])
    op.create_index('ix_tool_runs_tool', 'tool_runs', ['tool'])


def downgrade() -> None:
    op.drop_index('ix_tool_runs_tool', table_name='tool_runs')
    op.drop_index('ix_tool_runs_audit_id', table_name='tool_runs')
    op.drop_table('tool_runs')
