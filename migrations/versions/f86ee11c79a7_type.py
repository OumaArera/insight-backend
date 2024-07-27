"""type

Revision ID: f86ee11c79a7
Revises: 9f8ff7b31022
Create Date: 2024-07-27 21:18:32.125128

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'f86ee11c79a7'
down_revision = '9f8ff7b31022'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sessions_', schema=None) as batch_op:
        batch_op.alter_column('meeting_type',
               existing_type=postgresql.TIMESTAMP(),
               type_=sa.String(length=200),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sessions_', schema=None) as batch_op:
        batch_op.alter_column('meeting_type',
               existing_type=sa.String(length=200),
               type_=postgresql.TIMESTAMP(),
               existing_nullable=False)

    # ### end Alembic commands ###
