"""Fail closed on unreviewed or rolling-incompatible Alembic migrations."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import (
    MAX_INTAKE_JSON_BYTES,
    load_unique_json,
    read_stable_bytes,
)

VERSIONS = ROOT / "platform" / "migrations" / "versions"
BASELINE = ROOT / "deploy" / "migration-compatibility-baseline.json"
EXPECTED_BASELINE_HEAD = "0017_mail_token_hash_unique"
EXPECTED_HISTORY = {
    "0001_baseline.py": "9eac03d683fe06cc27ea2f90d5528d6e5444c95ef51208033b2e4888ea9253e7",
    "0002_oidc_and_roles.py": "26e06c79182c2ccca50ceb923bdbc83d6d636c1e1b6b8cb65233d7f283b37794",
    "0003_task_lifecycle.py": "2217c97abc03cafe5ec14ba958bdd5426d9f0a358a855e80fea78a29bc1fa20d",
    "0004_trace_ids.py": "daf26ce36632df593cc5967478a42e5b71344fcd5e8bb8c893175646a2266796",
    "0005_card_reveals.py": "6b974981be0352dfe1041e3ca904a8b52aa50817aba625fca4eb929fc4e78178",
    "0006_mail_worker_delivery.py": "5a1cdc1f0dfab9840627fb188546c24ff3248c39fd18901fbf7ed4e6ea9816b9",
    "0007_audit_append_only.py": "5dd58f007c7dc85976ba55f1e5e567bb8d98b86e78aca0a9ebd3d5300edd2a20",
    "0008_upload_outbox.py": "7bc91205450bcbd82a73d4a1f1dd00dbf6c1bfa1bad4d28a20fcc5fe2016111c",
    "0009_upload_policy_governance.py": "edd647e8ac6def7901f855faf65f42dbb7e906852611a293b0e428a41d4880ec",
    "0010_card_reveal_step_up.py": "a397021ea0942d76a612fdcd972c28201114619f1b6624954fd8610e22ccd218",
    "0011_mailbox_lease_and_code_ttl.py": "e258b2ea4b1c9b12cf4cf70fc7ce307b4505c551a26a92764301e4bdc926b42e",
    "0012_mail_session_tokens.py": "4e9480ef02a674604b2fa7b43e619264482e28e3cd2aa1b2249ae3a4c3bf0b4c",
    "0013_card_secret_ref_unique.py": "9a97aee1ba4677a6ea47cd79ebcf89836a2b121c3a2b716387e42abc6a6069e1",
    "0014_audit_evidence_fields.py": "2a6b686b6dc18837668add254e5757f8ae16de6ba81703dda76ebc5dd022bef2",
    "0015_mailbox_health.py": "169c409bb87a6f35c40ac1a4bb4bdb7d78ced81cb74faba0c0376e0fe476d734",
    "0016_device_last_seen.py": "10efb56b8be34ecee9b6bd135b452eca524b26e878aa2182dde17eab7091247f",
    "0017_mail_token_hash_unique.py": "e8ce7faea10f47687a1f4d3009a4d7e59494a9b59ae235c9b4d21edd1c168689",
}
FORBIDDEN_OPS = {
    "drop_column",
    "drop_constraint",
    "drop_index",
    "drop_table",
    "rename_table",
    "create_check_constraint",
    "create_foreign_key",
    "create_exclude_constraint",
    "create_primary_key",
    "create_unique_constraint",
}


def _literal_assignment(tree: ast.Module, name: str) -> str | None:
    for node in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if isinstance(target, ast.Name) and target.id == name:
            if isinstance(value, ast.Constant) and (
                isinstance(value.value, str) or value.value is None
            ):
                return value.value
            raise ValueError(f"{name} must be one string literal or None")
    raise ValueError(f"missing {name}")


def _call_root_name(call: ast.Call) -> tuple[str | None, str | None]:
    if not isinstance(call.func, ast.Attribute):
        return None, None
    method = call.func.attr
    value: ast.expr = call.func.value
    while isinstance(value, ast.Attribute):
        value = value.value
    return (value.id if isinstance(value, ast.Name) else None), method


def _constants(tree: ast.Module) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            for target in targets:
                if isinstance(target, ast.Name):
                    values[target.id] = value.value
    return values


def _literal_string(node: ast.expr, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_string(node.left, constants)
        right = _literal_string(node.right, constants)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                part = _literal_string(value.value, constants)
                if part is None:
                    return None
                parts.append(part)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.Call):
        _, method = _call_root_name(node)
        if method == "text" and len(node.args) == 1:
            return _literal_string(node.args[0], constants)
    return None


def _sql_code_only(sql: str) -> str:
    """Remove comments and quoted values before matching SQL control tokens."""

    result: list[str] = []
    index = 0
    state = "code"
    while index < len(sql):
        char = sql[index]
        pair = sql[index : index + 2]
        if state == "code":
            if pair == "--":
                state = "line-comment"
                result.append("  ")
                index += 2
                continue
            if pair == "/*":
                state = "block-comment"
                result.append("  ")
                index += 2
                continue
            if char == "'":
                state = "single-quote"
                result.append(" ")
            elif char == '"':
                state = "double-quote"
                result.append(" ")
            else:
                result.append(char)
        elif state == "line-comment":
            result.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            result.append(" ")
            if pair == "*/":
                result.append(" ")
                index += 1
                state = "code"
        elif state == "single-quote":
            result.append(" ")
            if pair == "''":
                result.append(" ")
                index += 1
            elif char == "'":
                state = "code"
        else:
            result.append(" ")
            if pair == '""':
                result.append(" ")
                index += 1
            elif char == '"':
                state = "code"
        index += 1
    return " ".join("".join(result).upper().split())


def _sql_error(sql: str) -> str | None:
    code = _sql_code_only(sql)
    # The first revision identifier over Alembic's default 32-character
    # version table boundary must widen only that metadata column.
    if re.fullmatch(
        r"ALTER TABLE ALEMBIC_VERSION ALTER COLUMN VERSION_NUM "
        r"TYPE VARCHAR\(255\);?",
        code,
    ):
        return None
    # Reviewed security invariant for revision 0020. Keep this exception
    # deliberately exact so CREATE TRIGGER cannot become a generic dynamic-SQL
    # escape hatch for later migrations.
    if re.fullmatch(
        r"CREATE TRIGGER AUDIT_EVENTS_SUBJECT_BINDING BEFORE INSERT ON "
        r"AUDIT_EVENTS FOR EACH ROW EXECUTE FUNCTION "
        r"AUDIT_EVENTS_VALIDATE_SUBJECT_BINDING\(\);?",
        code,
    ):
        return None
    reviewed_card_event_triggers = (
        r"CREATE TRIGGER CARD_EVENTS_NO_UPDATE BEFORE UPDATE ON CARD_EVENTS "
        r"FOR EACH ROW EXECUTE FUNCTION CARD_EVENTS_PREVENT_MUTATION\(\);?",
        r"CREATE TRIGGER CARD_EVENTS_NO_DELETE BEFORE DELETE ON CARD_EVENTS "
        r"FOR EACH ROW EXECUTE FUNCTION CARD_EVENTS_PREVENT_MUTATION\(\);?",
        r"CREATE TRIGGER CARD_EVENTS_SUBJECT_BINDING BEFORE INSERT ON CARD_EVENTS "
        r"FOR EACH ROW EXECUTE FUNCTION CARD_EVENTS_VALIDATE_SUBJECT_BINDING\(\);?",
    )
    if any(re.fullmatch(pattern, code) for pattern in reviewed_card_event_triggers):
        return None
    # Reviewed database binding invariant for revision 0038. Keep every trigger
    # target, event, column list and function exact; other dynamic SQL remains
    # forbidden by the generic rule below.
    reviewed_card_claim_binding_triggers = (
        r"CREATE TRIGGER POOL_IMPORT_CARD_IDENTITY_CLAIMS_CONTEXT_BINDING_INSERT "
        r"BEFORE INSERT ON POOL_IMPORT_CARD_IDENTITY_CLAIMS FOR EACH ROW EXECUTE "
        r"FUNCTION POOL_IMPORT_CARD_IDENTITY_CLAIMS_VALIDATE_CONTEXT_BINDING\(\);?",
        r"CREATE TRIGGER POOL_IMPORT_CARD_IDENTITY_CLAIMS_CONTEXT_BINDING_UPDATE "
        r"BEFORE UPDATE OF CONTEXT_ID, TENANT_ID ON "
        r"POOL_IMPORT_CARD_IDENTITY_CLAIMS FOR EACH ROW EXECUTE FUNCTION "
        r"POOL_IMPORT_CARD_IDENTITY_CLAIMS_VALIDATE_CONTEXT_BINDING\(\);?",
        r"CREATE TRIGGER POOL_IMPORT_CONTEXTS_CARD_CLAIM_BINDING BEFORE UPDATE OF "
        r"ID, TENANT_ID, POOL_TYPE ON POOL_IMPORT_CONTEXTS FOR EACH ROW EXECUTE "
        r"FUNCTION POOL_IMPORT_CONTEXTS_VALIDATE_CARD_CLAIM_BINDING\(\);?",
    )
    if any(
        re.fullmatch(pattern, code)
        for pattern in reviewed_card_claim_binding_triggers
    ):
        return None
    # Reviewed non-deletion invariant for revision 0039. Reclamation moves an
    # existing claim to the replacement context, so only this exact DELETE
    # trigger is permitted; all other trigger-shaped dynamic SQL stays blocked.
    if re.fullmatch(
        r"CREATE TRIGGER POOL_IMPORT_CARD_IDENTITY_CLAIMS_NO_DELETE BEFORE "
        r"DELETE ON POOL_IMPORT_CARD_IDENTITY_CLAIMS FOR EACH ROW EXECUTE "
        r"FUNCTION POOL_IMPORT_CARD_IDENTITY_CLAIMS_PREVENT_DELETE\(\);?",
        code,
    ):
        return None
    # Reviewed immutable identity invariant for revision 0040. Context and
    # position remain transferable by the audited reclamation path.
    if re.fullmatch(
        r"CREATE TRIGGER POOL_IMPORT_CARD_IDENTITY_CLAIMS_IDENTITY_IMMUTABLE "
        r"BEFORE UPDATE OF TENANT_ID, PROVIDER_REF ON "
        r"POOL_IMPORT_CARD_IDENTITY_CLAIMS FOR EACH ROW EXECUTE FUNCTION "
        r"POOL_IMPORT_CARD_IDENTITY_CLAIMS_PREVENT_IDENTITY_CHANGE\(\);?",
        code,
    ):
        return None
    # Reviewed append-only claim-location ledger for revision 0041. Keep the
    # source trigger and both ledger mutation guards exact.
    reviewed_card_claim_mutation_triggers = (
        r"CREATE TRIGGER POOL_IMPORT_CARD_CLAIM_MUTATIONS_RECORD AFTER UPDATE "
        r"OF CONTEXT_ID, POSITION ON POOL_IMPORT_CARD_IDENTITY_CLAIMS FOR EACH "
        r"ROW EXECUTE FUNCTION POOL_IMPORT_CARD_CLAIM_MUTATIONS_RECORD\(\);?",
        r"CREATE TRIGGER POOL_IMPORT_CARD_CLAIM_MUTATIONS_NO_UPDATE BEFORE "
        r"UPDATE ON POOL_IMPORT_CARD_CLAIM_MUTATIONS FOR EACH ROW EXECUTE "
        r"FUNCTION POOL_IMPORT_CARD_CLAIM_MUTATIONS_PREVENT_MUTATION\(\);?",
        r"CREATE TRIGGER POOL_IMPORT_CARD_CLAIM_MUTATIONS_NO_DELETE BEFORE "
        r"DELETE ON POOL_IMPORT_CARD_CLAIM_MUTATIONS FOR EACH ROW EXECUTE "
        r"FUNCTION POOL_IMPORT_CARD_CLAIM_MUTATIONS_PREVENT_MUTATION\(\);?",
    )
    if any(
        re.fullmatch(pattern, code)
        for pattern in reviewed_card_claim_mutation_triggers
    ):
        return None
    rules = (
        (r"\b(?:DROP|TRUNCATE|DELETE\s+FROM|RENAME\s+TABLE)\b", "destructive SQL"),
        (r"\bCREATE\s+UNIQUE\s+INDEX\b", "unique-index contract SQL"),
        (
            r"\bALTER\s+TABLE\b.*\b(?:DROP\s+COLUMN|RENAME|ADD\s+(?:CONSTRAINT|UNIQUE|CHECK|FOREIGN\s+KEY)|VALIDATE\s+CONSTRAINT)\b",
            "table contract SQL",
        ),
        (
            r"\bALTER\s+TABLE\b.*\bALTER\s+(?:COLUMN\s+)?[^ ]+\s+.*\b(?:TYPE|SET\s+NOT\s+NULL|DROP\s+DEFAULT)\b",
            "column contract SQL",
        ),
        (
            r"\bALTER\s+TABLE\b.*\bADD\s+COLUMN\b.*\b(?:REFERENCES|CHECK|UNIQUE)\b",
            "column constraint SQL",
        ),
        (r"\b(?:DO|EXECUTE|CALL)\b", "dynamic SQL requiring separate review"),
    )
    for pattern, label in rules:
        if re.search(pattern, code, flags=re.DOTALL):
            return label
    add_not_null = re.search(
        r"\bALTER\s+TABLE\b.*\bADD\s+COLUMN\b.*\bNOT\s+NULL\b", code
    )
    if add_not_null and " DEFAULT " not in f" {code} ":
        return "non-null column SQL without a server default"
    return None


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_none(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _upgrade_errors(path: Path, tree: ast.Module) -> list[str]:
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    upgrade = functions.get("upgrade")
    if upgrade is None:
        return [f"{path.name}: missing upgrade()"]
    constants = _constants(tree)
    pending = [upgrade]
    visited: set[str] = set()
    reachable: list[ast.FunctionDef] = []
    errors: list[str] = []
    while pending:
        function = pending.pop()
        if function.name in visited:
            continue
        visited.add(function.name)
        reachable.append(function)
        for node in ast.walk(function):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in functions:
                pending.append(functions[node.func.id])

    created_tables: set[str] = set()
    for function in reachable:
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            root, method = _call_root_name(node)
            if method != "create_table" or not (
                root == "op" or bool(root and root.endswith("_op"))
            ):
                continue
            table = node.args[0] if node.args else _keyword(node, "table_name")
            table_name = _literal_string(table, constants) if table is not None else None
            if table_name is not None:
                created_tables.add(table_name)

    for function in reachable:
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            root, method = _call_root_name(node)
            if method is None:
                continue
            # Alembic's operation proxy may be imported or assigned under an alias.
            # Method matching keeps those aliases from bypassing the review.
            op_call = (
                root == "op"
                or bool(root and root.endswith("_op"))
                or method in FORBIDDEN_OPS | {"add_column", "alter_column", "create_index"}
            )
            if op_call and method in FORBIDDEN_OPS:
                errors.append(f"{path.name}:{node.lineno}: forbidden {method} in upgrade")
            elif op_call and method == "alter_column":
                nullable = _keyword(node, "nullable")
                server_default = _keyword(node, "server_default")
                if nullable is not None and not (
                    isinstance(nullable, ast.Constant) and nullable.value is True
                ):
                    errors.append(
                        f"{path.name}:{node.lineno}: nullable must be literal True for an expand change"
                    )
                if _keyword(node, "type_") is not None or _keyword(node, "new_column_name") is not None:
                    errors.append(f"{path.name}:{node.lineno}: column type/rename is a contract change")
                if server_default is not None and _is_none(server_default):
                    errors.append(f"{path.name}:{node.lineno}: dropping a server default is a contract change")
            elif op_call and method == "add_column":
                column = node.args[1] if len(node.args) > 1 else _keyword(node, "column")
                if isinstance(column, ast.Call):
                    nullable = _keyword(column, "nullable")
                    server_default = _keyword(column, "server_default")
                    if _is_false(nullable) and (server_default is None or _is_none(server_default)):
                        errors.append(
                            f"{path.name}:{node.lineno}: non-null column requires a server default"
                        )
                else:
                    errors.append(f"{path.name}:{node.lineno}: add_column must use a literal sa.Column")
            elif op_call and method == "create_index":
                unique = _keyword(node, "unique")
                table = node.args[1] if len(node.args) > 1 else _keyword(node, "table_name")
                table_name = _literal_string(table, constants) if table is not None else None
                unique_on_new_table = _is_true(unique) and table_name in created_tables
                if unique is not None and not _is_false(unique) and not unique_on_new_table:
                    errors.append(
                        f"{path.name}:{node.lineno}: unique must be literal False unless the table is created in the same upgrade"
                    )
            if method == "execute":
                if not node.args:
                    errors.append(f"{path.name}:{node.lineno}: execute SQL is missing")
                    continue
                sql = _literal_string(node.args[0], constants)
                if sql is None:
                    errors.append(f"{path.name}:{node.lineno}: dynamic SQL cannot be reviewed")
                    continue
                sql_error = _sql_error(sql)
                if sql_error:
                    errors.append(f"{path.name}:{node.lineno}: {sql_error}")
    return errors


def _load_migration(path: Path, raw: bytes) -> tuple[str, str | None, ast.Module]:
    tree = ast.parse(raw.decode("utf-8"), filename=str(path))
    return (
        _literal_assignment(tree, "revision"),
        _literal_assignment(tree, "down_revision"),
        tree,
    )


def verification_errors(
    migrations_dir: Path = VERSIONS,
    baseline_data: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    if baseline_data is None:
        try:
            baseline_data = load_unique_json(
                BASELINE,
                max_bytes=MAX_INTAKE_JSON_BYTES,
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return [f"cannot load migration baseline: {exc}"]
    if not isinstance(baseline_data, dict):
        return ["migration baseline must be a JSON object"]
    if baseline_data.get("schema_version") != 1:
        errors.append("baseline schema_version must be 1")
    if baseline_data.get("baseline_head") != EXPECTED_BASELINE_HEAD:
        errors.append(f"baseline head must remain {EXPECTED_BASELINE_HEAD}")
    history = baseline_data.get("reviewed_history")
    expansions = baseline_data.get("reviewed_expansions")
    if history != EXPECTED_HISTORY:
        errors.append("reviewed history differs from the code-anchored baseline")
    if not isinstance(expansions, dict) or not all(
        isinstance(name, str) and isinstance(digest, str)
        for name, digest in (expansions.items() if isinstance(expansions, dict) else [])
    ):
        errors.append("reviewed_expansions must map filenames to SHA-256 strings")
        expansions = {}

    paths = sorted(
        path for path in migrations_dir.glob("*.py") if path.name != "__init__.py"
    )
    path_by_name = {path.name: path for path in paths}
    expected_names = set(EXPECTED_HISTORY)
    actual_names = set(path_by_name)
    missing = expected_names - actual_names
    if missing:
        errors.append("missing baseline migrations: " + ", ".join(sorted(missing)))
    new_names = actual_names - expected_names
    unreviewed = new_names - set(expansions)
    stale_reviews = set(expansions) - new_names
    if unreviewed:
        errors.append("unreviewed new migrations: " + ", ".join(sorted(unreviewed)))
    if stale_reviews:
        errors.append("reviewed_expansions contains absent files: " + ", ".join(sorted(stale_reviews)))

    migrations: dict[str, tuple[str | None, str, ast.Module]] = {}
    trees_by_name: dict[str, ast.Module] = {}
    for name, path in path_by_name.items():
        expected_digest = EXPECTED_HISTORY.get(name, expansions.get(name))
        try:
            raw = read_stable_bytes(path, max_bytes=MAX_INTAKE_JSON_BYTES)
        except OSError as exc:
            errors.append(f"{name}: invalid migration metadata: {exc}")
            continue
        if expected_digest and hashlib.sha256(raw).hexdigest() != expected_digest:
            errors.append(f"{name}: SHA-256 differs from its reviewed value")
        try:
            revision, down_revision, tree = _load_migration(path, raw)
        except (UnicodeError, SyntaxError, ValueError) as exc:
            errors.append(f"{name}: invalid migration metadata: {exc}")
            continue
        if revision in migrations:
            errors.append(f"duplicate revision: {revision}")
        migrations[revision] = (down_revision, name, tree)
        trees_by_name[name] = tree

    children: dict[str | None, list[str]] = {}
    for revision, (down_revision, _, _) in migrations.items():
        children.setdefault(down_revision, []).append(revision)
        if down_revision is not None and down_revision not in migrations:
            errors.append(f"{revision}: missing parent revision {down_revision}")
    roots = children.get(None, [])
    if roots != ["0001_baseline"]:
        errors.append(f"migration chain must have only the reviewed root, found {roots}")
    for parent, revisions in children.items():
        if parent is not None and len(revisions) > 1:
            errors.append(f"migration chain branches after {parent}: {sorted(revisions)}")
    heads = sorted(set(migrations) - {parent for parent in children if parent is not None})
    if len(heads) != 1:
        errors.append(f"migration chain must have one head, found {heads}")

    cursor: str | None = "0001_baseline"
    seen: set[str] = set()
    while cursor is not None and cursor in migrations and cursor not in seen:
        seen.add(cursor)
        next_revisions = children.get(cursor, [])
        cursor = next_revisions[0] if len(next_revisions) == 1 else None
    if EXPECTED_BASELINE_HEAD not in seen:
        errors.append(f"reviewed baseline chain does not reach {EXPECTED_BASELINE_HEAD}")
    if seen != set(migrations):
        errors.append("not every migration belongs to the single reviewed chain")

    for name in sorted(new_names & set(expansions)):
        path = path_by_name[name]
        tree = trees_by_name.get(name)
        if tree is not None:
            errors.extend(_upgrade_errors(path, tree))
    return errors


def main() -> int:
    errors = verification_errors()
    if errors:
        for error in errors:
            print(f"migration-compatibility-error: {error}", file=sys.stderr)
        return 1
    print(
        "migration-compatibility-ok "
        f"baseline={EXPECTED_BASELINE_HEAD} reviewed-expansions-valid"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
