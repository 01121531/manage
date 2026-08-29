"""Make opaque mail-session token hashes globally unique.

Revision ID: 0017_mail_token_hash_unique
Revises: 0016_device_last_seen
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0017_mail_token_hash_unique"
down_revision: str | None = "0016_device_last_seen"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONSTRAINT = "uq_mail_sessions_session_token_hash"


def upgrade() -> None:
    context = op.get_context()
    duplicate_query = (
        "SELECT session_token_hash FROM mail_sessions "
        "GROUP BY session_token_hash HAVING COUNT(*) > 1"
    )
    if context.as_sql:
        op.execute(
            sa.text(
                "DO $$ BEGIN "
                f"IF EXISTS ({duplicate_query}) THEN "
                "RAISE EXCEPTION 'duplicate mail-session token hashes must be "
                "remediated before migration'; "
                "END IF; END $$"
            )
        )
    else:
        duplicate = op.get_bind().execute(sa.text(duplicate_query)).first()
        if duplicate is not None:
            raise RuntimeError(
                "Duplicate mail-session token hashes must be remediated before migration"
            )
    with op.batch_alter_table("mail_sessions") as batch_op:
        batch_op.create_unique_constraint(_CONSTRAINT, ["session_token_hash"])


def downgrade() -> None:
    with op.batch_alter_table("mail_sessions") as batch_op:
        batch_op.drop_constraint(_CONSTRAINT, type_="unique")
