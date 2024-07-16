"""change column details

Revision ID: 1292ecd75a0c
Revises: 6d3ae05a4598
Create Date: 2024-07-16 16:32:02.052774

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '1292ecd75a0c'
down_revision = '6d3ae05a4598'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('patient_id', sa.Integer(), nullable=True))
        batch_op.drop_column('patient_details')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('patient_details', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True))
        batch_op.drop_column('patient_id')

    # ### end Alembic commands ###
