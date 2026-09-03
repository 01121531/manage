import copy
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import verify_migration_compatibility as migration_compatibility
from scripts.external_json import read_stable_bytes
from scripts.verify_migration_compatibility import BASELINE, VERSIONS, verification_errors


SAFE_EXPANSION = '''from alembic import op
import sqlalchemy as sa

revision = "0031_expand"
down_revision = "0047_pool_import_receipt_context_binding"

def _backfill():
    # DROP TABLE comments and string literals are not SQL operations.
    op.execute(sa.text("-- DROP TABLE ignored\\nUPDATE users SET email = email"))

def upgrade():
    """A DROP COLUMN phrase in a docstring is not executable."""
    op.add_column("users", sa.Column("nickname", sa.String(), nullable=True))
    op.add_column(
        "users",
        sa.Column("display_name", sa.String(), nullable=False, server_default=""),
    )
    op.create_index("ix_users_nickname", "users", ["nickname"], unique=False)
    _backfill()

def downgrade():
    op.drop_index("ix_users_nickname", table_name="users")
    op.drop_column("users", "display_name")
    op.drop_column("users", "nickname")
'''


SAFE_NEW_TABLE_UNIQUE = '''from alembic import op
import sqlalchemy as sa

revision = "0031_expand"
down_revision = "0047_pool_import_receipt_context_binding"

def upgrade():
    op.create_table(
        "new_requests",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("request_key", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_new_requests_request_key",
        "new_requests",
        ["request_key"],
        unique=True,
    )

def downgrade():
    op.drop_index("uq_new_requests_request_key", table_name="new_requests")
    op.drop_table("new_requests")
'''


class MigrationCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.migrations = Path(self.temporary.name) / "versions"
        shutil.copytree(VERSIONS, self.migrations)
        self.baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def add_reviewed(self, source: str, filename: str = "0031_expand.py") -> Path:
        path = self.migrations / filename
        path.write_text(source, encoding="utf-8")
        self.baseline["reviewed_expansions"][filename] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        return path

    def test_current_reviewed_baseline_is_exact_and_single_headed(self) -> None:
        self.assertEqual(verification_errors(), [])

    def test_reviewed_expand_and_backfill_pass_but_downgrade_is_not_scanned(self) -> None:
        self.add_reviewed(SAFE_EXPANSION)
        self.assertEqual(
            verification_errors(self.migrations, self.baseline),
            [],
        )

    def test_unique_index_on_a_table_created_in_the_same_upgrade_is_expand_safe(self) -> None:
        self.add_reviewed(SAFE_NEW_TABLE_UNIQUE)
        self.assertEqual(verification_errors(self.migrations, self.baseline), [])

    def test_safe_but_unreviewed_revision_is_rejected(self) -> None:
        (self.migrations / "0031_expand.py").write_text(
            SAFE_EXPANSION, encoding="utf-8"
        )
        errors = verification_errors(self.migrations, self.baseline)
        self.assertTrue(any("unreviewed new migrations" in error for error in errors), errors)

    def test_unreviewed_revision_cannot_hide_behind_an_unusual_filename(self) -> None:
        (self.migrations / "hidden_expand.py").write_text(
            SAFE_EXPANSION, encoding="utf-8"
        )
        errors = verification_errors(self.migrations, self.baseline)
        self.assertTrue(any("hidden_expand.py" in error for error in errors), errors)

    def test_baseline_head_history_and_file_tampering_are_rejected(self) -> None:
        cases = []
        changed_head = copy.deepcopy(self.baseline)
        changed_head["baseline_head"] = "0016_device_last_seen"
        cases.append(("head", self.migrations, changed_head))

        changed_history = copy.deepcopy(self.baseline)
        changed_history["reviewed_history"]["0001_baseline.py"] = "0" * 64
        cases.append(("manifest hash", self.migrations, changed_history))

        tampered_dir = Path(self.temporary.name) / "tampered"
        shutil.copytree(self.migrations, tampered_dir)
        with (tampered_dir / "0001_baseline.py").open("a", encoding="utf-8") as handle:
            handle.write("\n# unauthorized baseline change\n")
        cases.append(("migration file", tampered_dir, self.baseline))

        for label, directory, baseline in cases:
            with self.subTest(label=label):
                self.assertTrue(verification_errors(directory, baseline))

    def test_each_migration_is_read_once_through_the_64_kib_stable_boundary(
        self,
    ) -> None:
        self.add_reviewed(SAFE_EXPANSION)
        calls: list[tuple[Path, int]] = []

        def tracked_read(path: Path, *, max_bytes: int) -> bytes:
            calls.append((path, max_bytes))
            return read_stable_bytes(path, max_bytes=max_bytes)

        with mock.patch.object(
            migration_compatibility,
            "read_stable_bytes",
            side_effect=tracked_read,
        ):
            self.assertEqual(
                verification_errors(self.migrations, self.baseline),
                [],
            )

        expected_names = sorted(
            path.name
            for path in self.migrations.glob("*.py")
            if path.name != "__init__.py"
        )
        self.assertEqual(sorted(path.name for path, _ in calls), expected_names)
        self.assertTrue(all(max_bytes == 64 * 1024 for _, max_bytes in calls))

    def test_migration_over_64_kib_is_rejected(self) -> None:
        raw = SAFE_EXPANSION.encode("utf-8")
        raw += b"\n#" + b"x" * (64 * 1024 + 1 - len(raw) - 2)
        path = self.migrations / "0031_expand.py"
        path.write_bytes(raw)
        self.baseline["reviewed_expansions"][path.name] = hashlib.sha256(raw).hexdigest()

        errors = verification_errors(self.migrations, self.baseline)

        self.assertTrue(
            any(
                error.startswith("0031_expand.py: invalid migration metadata:")
                for error in errors
            ),
            errors,
        )

    def test_non_regular_migration_is_rejected(self) -> None:
        path = self.migrations / "0031_expand.py"
        path.mkdir()
        self.baseline["reviewed_expansions"][path.name] = "0" * 64

        errors = verification_errors(self.migrations, self.baseline)

        self.assertTrue(
            any(
                error.startswith("0031_expand.py: invalid migration metadata:")
                for error in errors
            ),
            errors,
        )

    def test_link_or_reparse_migration_is_rejected_before_open(self) -> None:
        path = self.add_reviewed(SAFE_EXPANSION)
        real_open = os.open
        opened_target = False

        def tracked_open(candidate: object, flags: int, *args: object) -> int:
            nonlocal opened_target
            if Path(candidate) == path:
                opened_target = True
            return real_open(candidate, flags, *args)

        with mock.patch(
            "scripts.external_json.has_link_or_reparse_ancestor",
            side_effect=lambda candidate: Path(candidate) == path,
        ), mock.patch("scripts.external_json.os.open", side_effect=tracked_open):
            errors = verification_errors(self.migrations, self.baseline)

        self.assertFalse(opened_target)
        self.assertTrue(
            any(
                error.startswith("0031_expand.py: invalid migration metadata:")
                for error in errors
            ),
            errors,
        )

    def test_invalid_utf8_migration_is_rejected(self) -> None:
        path = self.migrations / "0031_expand.py"
        raw = SAFE_EXPANSION.encode("utf-8") + b"\xff"
        path.write_bytes(raw)
        self.baseline["reviewed_expansions"][path.name] = hashlib.sha256(raw).hexdigest()

        errors = verification_errors(self.migrations, self.baseline)

        self.assertTrue(
            any(
                error.startswith("0031_expand.py: invalid migration metadata:")
                for error in errors
            ),
            errors,
        )

    def test_migration_read_shape_drift_is_rejected(self) -> None:
        real_fstat = os.fstat
        calls = 0

        def drifting_fstat(descriptor: int) -> os.stat_result:
            nonlocal calls
            calls += 1
            metadata = real_fstat(descriptor)
            if calls == 2:
                values = list(metadata)
                values[6] = metadata.st_size + 1
                return os.stat_result(values)
            return metadata

        with mock.patch("scripts.external_json.os.fstat", side_effect=drifting_fstat):
            errors = verification_errors(self.migrations, self.baseline)

        self.assertTrue(
            any(
                error.startswith("0001_baseline.py: invalid migration metadata:")
                for error in errors
            ),
            errors,
        )

    def test_branch_missing_parent_and_stale_review_are_rejected(self) -> None:
        broken = SAFE_EXPANSION.replace(
            'down_revision = "0047_pool_import_receipt_context_binding"',
            'down_revision = "missing_parent"',
        )
        self.add_reviewed(broken)
        errors = verification_errors(self.migrations, self.baseline)
        self.assertTrue(any("missing parent revision" in error for error in errors), errors)

        self.baseline["reviewed_expansions"]["0022_absent.py"] = "1" * 64
        errors = verification_errors(self.migrations, self.baseline)
        self.assertTrue(any("absent files" in error for error in errors), errors)

    def test_destructive_and_contract_upgrade_operations_are_rejected(self) -> None:
        unsafe_bodies = {
            "drop column": 'op.drop_column("users", "email")',
            "aliased drop": 'operations.drop_column("users", "email")',
            "helper drop table": 'dangerous()\n\ndef dangerous():\n    op.drop_table("users")',
            "unique constraint": 'op.create_unique_constraint("uq", "users", ["email"])',
            "unique index": 'op.create_index("uq", "users", ["email"], unique=True)',
            "dynamic unique": 'op.create_index("uq", "users", ["email"], unique=is_unique)',
            "non-null add": 'op.add_column("users", sa.Column("x", sa.String(), nullable=False))',
            "narrow alter": 'op.alter_column("users", "email", type_=sa.String(10))',
            "dynamic nullable": 'op.alter_column("users", "email", nullable=desired_nullable)',
            "raw drop": 'op.execute(sa.text("DROP TABLE users"))',
            "raw set not null": 'op.execute("ALTER TABLE users ALTER COLUMN email SET NOT NULL")',
            "raw non-null add": 'op.execute("ALTER TABLE users ADD COLUMN x TEXT NOT NULL")',
            "version table wrong target": (
                'op.execute("ALTER TABLE users ALTER COLUMN version_num TYPE VARCHAR(255)")'
            ),
            "version table wrong width": (
                'op.execute("ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(32)")'
            ),
            "version table statement suffix": (
                'op.execute("ALTER TABLE alembic_version ALTER COLUMN version_num '
                'TYPE VARCHAR(255); SELECT 1")'
            ),
            "different trigger target": (
                'op.execute("CREATE TRIGGER audit_events_subject_binding BEFORE INSERT ON users '
                'FOR EACH ROW EXECUTE FUNCTION audit_events_validate_subject_binding()")'
            ),
            "different trigger event": (
                'op.execute("CREATE TRIGGER audit_events_subject_binding BEFORE UPDATE ON audit_events '
                'FOR EACH ROW EXECUTE FUNCTION audit_events_validate_subject_binding()")'
            ),
            "trigger statement suffix": (
                'op.execute("CREATE TRIGGER audit_events_subject_binding BEFORE INSERT ON audit_events '
                'FOR EACH ROW EXECUTE FUNCTION audit_events_validate_subject_binding(); SELECT 1")'
            ),
            "card claim trigger wrong target": (
                'op.execute("CREATE TRIGGER pool_import_card_identity_claims_context_binding_insert '
                'BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_card_identity_claims_validate_context_binding()")'
            ),
            "card claim trigger wrong event": (
                'op.execute("CREATE TRIGGER pool_import_card_identity_claims_context_binding_insert '
                'BEFORE UPDATE ON pool_import_card_identity_claims FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_card_identity_claims_validate_context_binding()")'
            ),
            "card claim trigger statement suffix": (
                'op.execute("CREATE TRIGGER pool_import_card_identity_claims_context_binding_insert '
                'BEFORE INSERT ON pool_import_card_identity_claims FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_card_identity_claims_validate_context_binding(); SELECT 1")'
            ),
            "card claim delete guard wrong target": (
                'op.execute("CREATE TRIGGER pool_import_card_identity_claims_no_delete '
                'BEFORE DELETE ON users FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_card_identity_claims_prevent_delete()")'
            ),
            "card claim delete guard wrong event": (
                'op.execute("CREATE TRIGGER pool_import_card_identity_claims_no_delete '
                'BEFORE UPDATE ON pool_import_card_identity_claims FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_card_identity_claims_prevent_delete()")'
            ),
            "card claim delete guard statement suffix": (
                'op.execute("CREATE TRIGGER pool_import_card_identity_claims_no_delete '
                'BEFORE DELETE ON pool_import_card_identity_claims FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_card_identity_claims_prevent_delete(); SELECT 1")'
            ),
            "card claim identity guard wrong target": (
                'op.execute("CREATE TRIGGER pool_import_card_identity_claims_identity_immutable '
                'BEFORE UPDATE OF tenant_id, provider_ref ON users FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_card_identity_claims_prevent_identity_change()")'
            ),
            "card claim identity guard wrong columns": (
                'op.execute("CREATE TRIGGER pool_import_card_identity_claims_identity_immutable '
                'BEFORE UPDATE OF context_id, provider_ref ON '
                'pool_import_card_identity_claims FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_card_identity_claims_prevent_identity_change()")'
            ),
            "card claim identity guard statement suffix": (
                'op.execute("CREATE TRIGGER pool_import_card_identity_claims_identity_immutable '
                'BEFORE UPDATE OF tenant_id, provider_ref ON '
                'pool_import_card_identity_claims FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_card_identity_claims_prevent_identity_change(); SELECT 1")'
            ),
            "card claim mutation record wrong target": (
                'op.execute("CREATE TRIGGER pool_import_card_claim_mutations_record '
                'AFTER UPDATE OF context_id, position ON users FOR EACH ROW '
                'EXECUTE FUNCTION pool_import_card_claim_mutations_record()")'
            ),
            "card claim mutation guard wrong event": (
                'op.execute("CREATE TRIGGER pool_import_card_claim_mutations_no_update '
                'BEFORE INSERT ON pool_import_card_claim_mutations FOR EACH ROW '
                'EXECUTE FUNCTION '
                'pool_import_card_claim_mutations_prevent_mutation()")'
            ),
            "card claim mutation guard statement suffix": (
                'op.execute("CREATE TRIGGER pool_import_card_claim_mutations_no_delete '
                'BEFORE DELETE ON pool_import_card_claim_mutations FOR EACH ROW '
                'EXECUTE FUNCTION '
                'pool_import_card_claim_mutations_prevent_mutation(); SELECT 1")'
            ),
            "pool context identity guard wrong target": (
                'op.execute("CREATE TRIGGER pool_import_contexts_identity_immutable '
                'BEFORE UPDATE OF id, context_token_hash, tenant_id, audience, '
                'pool_type, ordered_manifest_digest, item_count, created_by, '
                'device_id, trace_id, created_at ON users FOR EACH ROW EXECUTE '
                'FUNCTION pool_import_contexts_prevent_identity_change()")'
            ),
            "pool context identity guard wrong columns": (
                'op.execute("CREATE TRIGGER pool_import_contexts_identity_immutable '
                'BEFORE UPDATE OF id, context_token_hash, tenant_id, audience, '
                'pool_type, ordered_manifest_digest, item_count, created_by, '
                'device_id, trace_id, expires_at ON pool_import_contexts FOR EACH '
                'ROW EXECUTE FUNCTION '
                'pool_import_contexts_prevent_identity_change()")'
            ),
            "pool context identity guard statement suffix": (
                'op.execute("CREATE TRIGGER pool_import_contexts_identity_immutable '
                'BEFORE UPDATE OF id, context_token_hash, tenant_id, audience, '
                'pool_type, ordered_manifest_digest, item_count, created_by, '
                'device_id, trace_id, created_at ON pool_import_contexts FOR EACH '
                'ROW EXECUTE FUNCTION '
                'pool_import_contexts_prevent_identity_change(); SELECT 1")'
            ),
            "secure consumption guard wrong target": (
                'op.execute("CREATE TRIGGER '
                'secure_pool_import_consumptions_append_only BEFORE UPDATE OR '
                'DELETE ON pool_import_receipts FOR EACH ROW EXECUTE FUNCTION '
                'secure_pool_import_consumptions_prevent_mutation()")'
            ),
            "secure consumption guard wrong events": (
                'op.execute("CREATE TRIGGER '
                'secure_pool_import_consumptions_append_only BEFORE UPDATE ON '
                'secure_pool_import_consumptions FOR EACH ROW EXECUTE FUNCTION '
                'secure_pool_import_consumptions_prevent_mutation()")'
            ),
            "secure consumption guard statement suffix": (
                'op.execute("CREATE TRIGGER '
                'secure_pool_import_consumptions_append_only BEFORE UPDATE OR '
                'DELETE ON secure_pool_import_consumptions FOR EACH ROW EXECUTE '
                'FUNCTION secure_pool_import_consumptions_prevent_mutation(); '
                'SELECT 1")'
            ),
            "context consumption lifecycle wrong target": (
                'op.execute("CREATE TRIGGER '
                'pool_import_contexts_consumption_lifecycle BEFORE INSERT OR '
                'UPDATE OF expires_at, consumed_at, pool_import_receipt_id ON '
                'users FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_contexts_validate_consumption_lifecycle()")'
            ),
            "context consumption lifecycle wrong event": (
                'op.execute("CREATE TRIGGER '
                'pool_import_contexts_consumption_lifecycle BEFORE UPDATE OF '
                'expires_at, consumed_at, pool_import_receipt_id ON '
                'pool_import_contexts FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_contexts_validate_consumption_lifecycle()")'
            ),
            "context consumption lifecycle statement suffix": (
                'op.execute("CREATE TRIGGER '
                'pool_import_contexts_consumption_lifecycle BEFORE INSERT OR '
                'UPDATE OF expires_at, consumed_at, pool_import_receipt_id ON '
                'pool_import_contexts FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_contexts_validate_consumption_lifecycle(); '
                'SELECT 1")'
            ),
            "pool import receipt guard wrong target": (
                'op.execute("CREATE TRIGGER pool_import_receipts_append_only '
                'BEFORE UPDATE OR DELETE ON users FOR EACH ROW EXECUTE '
                'FUNCTION pool_import_receipts_prevent_mutation()")'
            ),
            "pool import receipt guard wrong events": (
                'op.execute("CREATE TRIGGER pool_import_receipts_append_only '
                'BEFORE UPDATE ON pool_import_receipts FOR EACH ROW EXECUTE '
                'FUNCTION pool_import_receipts_prevent_mutation()")'
            ),
            "pool import receipt guard statement suffix": (
                'op.execute("CREATE TRIGGER pool_import_receipts_append_only '
                'BEFORE UPDATE OR DELETE ON pool_import_receipts FOR EACH ROW '
                'EXECUTE FUNCTION pool_import_receipts_prevent_mutation(); '
                'SELECT 1")'
            ),
            "pool import context delete guard wrong target": (
                'op.execute("CREATE TRIGGER pool_import_contexts_no_delete '
                'BEFORE DELETE ON users FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_contexts_prevent_delete()")'
            ),
            "pool import context delete guard wrong events": (
                'op.execute("CREATE TRIGGER pool_import_contexts_no_delete '
                'BEFORE UPDATE ON pool_import_contexts FOR EACH ROW EXECUTE '
                'FUNCTION pool_import_contexts_prevent_delete()")'
            ),
            "pool import context delete guard statement suffix": (
                'op.execute("CREATE TRIGGER pool_import_contexts_no_delete '
                'BEFORE DELETE ON pool_import_contexts FOR EACH ROW EXECUTE '
                'FUNCTION pool_import_contexts_prevent_delete(); SELECT 1")'
            ),
            "pool import receipt context binding wrong target": (
                'op.execute("CREATE TRIGGER pool_import_receipts_context_binding '
                'BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION '
                'pool_import_receipts_validate_context_binding()")'
            ),
            "pool import receipt context binding wrong event": (
                'op.execute("CREATE TRIGGER pool_import_receipts_context_binding '
                'BEFORE UPDATE ON pool_import_receipts FOR EACH ROW EXECUTE '
                'FUNCTION pool_import_receipts_validate_context_binding()")'
            ),
            "pool import receipt context binding statement suffix": (
                'op.execute("CREATE TRIGGER pool_import_receipts_context_binding '
                'BEFORE INSERT ON pool_import_receipts FOR EACH ROW EXECUTE '
                'FUNCTION pool_import_receipts_validate_context_binding(); '
                'SELECT 1")'
            ),
            "dynamic sql": 'statement = make_sql()\n    op.execute(statement)',
        }
        for label, body in unsafe_bodies.items():
            with self.subTest(label=label):
                directory = Path(self.temporary.name) / label.replace(" ", "-")
                shutil.copytree(VERSIONS, directory)
                baseline = copy.deepcopy(self.baseline)
                source = f'''from alembic import op
import sqlalchemy as sa
revision = "0031_expand"
down_revision = "0047_pool_import_receipt_context_binding"
def upgrade():
    {body}
def downgrade():
    pass
'''
                path = directory / "0031_expand.py"
                path.write_text(source, encoding="utf-8")
                baseline["reviewed_expansions"][path.name] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                errors = verification_errors(directory, baseline)
                self.assertTrue(
                    any(
                        marker in error
                        for error in errors
                        for marker in (
                            "forbidden",
                            "contract",
                            "non-null",
                            "destructive",
                            "dynamic SQL",
                            "literal",
                        )
                    ),
                    errors,
                )

if __name__ == "__main__":
    unittest.main()
