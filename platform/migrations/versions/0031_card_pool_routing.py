"""Add server-owned card pool routing and frozen selection snapshots.

Revision ID: 0031_card_pool_routing
Revises: 0030_mailbox_task_routing
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0031_card_pool_routing"
down_revision: str | None = "0030_mailbox_task_routing"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


LEGACY_RULE = (
    '{"allocation_order":"oldest_available","brands":[],'
    '"minimum_validity_days":0,"pool_key":"legacy-unclassified",'
    '"region":"legacy-unclassified","task_type":"card_checkout"}'
)
LEGACY_RULES = f"[{LEGACY_RULE}]"


def upgrade() -> None:
    op.add_column(
        "cards",
        sa.Column(
            "pool_key",
            sa.String(length=80),
            server_default="legacy-unclassified",
            nullable=False,
        ),
    )
    op.add_column(
        "cards",
        sa.Column(
            "region",
            sa.String(length=80),
            server_default="legacy-unclassified",
            nullable=False,
        ),
    )
    op.create_index("ix_cards_pool_key", "cards", ["pool_key"])
    op.create_index("ix_cards_region", "cards", ["region"])
    op.create_index(
        "ix_cards_tenant_pool_region_brand",
        "cards",
        ["tenant_id", "pool_key", "region", "brand"],
    )

    op.add_column(
        "operational_policy_versions",
        sa.Column("selection_rules_json", sa.Text(), nullable=True),
    )
    op.execute(
        "UPDATE operational_policy_versions SET selection_rules_json = "
        "'[{\"allocation_order\":\"oldest_available\",\"brands\":[],"
        "\"minimum_validity_days\"\\:0,\"pool_key\":\"legacy-unclassified\","
        "\"region\":\"legacy-unclassified\",\"task_type\":\"card_checkout\"}]' "
        "WHERE domain = 'card'"
    )
    op.add_column(
        "card_allocations",
        sa.Column(
            "selection_rule_json",
            sa.Text(),
            server_default=LEGACY_RULE,
            nullable=False,
        ),
    )


def downgrade() -> None:
    with op.batch_alter_table("card_allocations") as batch_op:
        batch_op.drop_column("selection_rule_json")
    with op.batch_alter_table("operational_policy_versions") as batch_op:
        batch_op.drop_column("selection_rules_json")
    op.drop_index("ix_cards_tenant_pool_region_brand", table_name="cards")
    op.drop_index("ix_cards_region", table_name="cards")
    op.drop_index("ix_cards_pool_key", table_name="cards")
    with op.batch_alter_table("cards") as batch_op:
        batch_op.drop_column("region")
        batch_op.drop_column("pool_key")
