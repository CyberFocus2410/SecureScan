"""Add finding lifecycle columns for Step 15.

Revision ID: 004
Revises: 003
Create Date: 2026-11-21 09:30:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '004_add_finding_lifecycle_columns'
down_revision: Union[str, None] = '003_add_unified_findings_and_targets'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('findings') as batch_op:
        batch_op.add_column(sa.Column('status_reason', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('status_expires_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('status_updated_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('findings') as batch_op:
        batch_op.drop_column('status_updated_at')
        batch_op.drop_column('status_expires_at')
        batch_op.drop_column('status_reason')
