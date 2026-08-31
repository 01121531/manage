"""Verify the chapter-12 delivery matrix cannot overstate production readiness."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import MAX_INTAKE_JSON_BYTES, load_unique_json

MATRIX = ROOT / "deploy" / "phase-acceptance-matrix.json"
TOP_LEVEL_KEYS = {"schema_version", "plan_chapter", "production_acceptance", "phases"}
PHASE_KEYS = {
    "phase",
    "scope",
    "acceptance_criterion",
    "repository_status",
    "production_acceptance",
    "target_evidence_required",
    "missing_inputs",
}
EXPECTED = (
    (0, "确认 Sub2 API、卡字段、邮箱供应商、角色和部署环境", "形成接口样例、数据分类、合规边界和不可变更项", "boundary_partial"),
    (1, "FastAPI/React/PostgreSQL/Keycloak/Vault 骨架、CI/CD", "能登录、鉴权、审计、生成 OpenAPI 和前端客户端", "repository_gate_passed"),
    (2, "任务、邮箱连接器、mail session、验证码 API", "EXE 能登录并只通过 session 获取验证码；原始凭据不出服务端", "repository_gate_passed"),
    (3, "卡池、分配、租约、掩码和一次性揭示", "并发分配无重复；用户无法越权；完整动作有审计", "repository_gate_passed"),
    (4, "Sub2 Adapter、策略、幂等、未知结果核对", "客户端无 Sub2 配置；成功/失败/未知可区分和回放", "generic_adapter_gate_passed"),
    (5, "EXE 登录改造、平台任务工作台、自动填充适配", "现有连续复制/粘贴体验保留，注销/过期可安全停止", "repository_gate_passed"),
    (6, "小范围试点、监控、培训、回滚演练", "试点用户全流程完成；无越权、无敏感日志、可追溯", "preflight_only"),
)


def _nonempty_strings(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and item.strip() == item and bool(item) for item in value
    )


def matrix_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != TOP_LEVEL_KEYS:
        return ["matrix top-level schema is invalid"]
    errors: list[str] = []
    if document.get("schema_version") != 1 or document.get("plan_chapter") != "12":
        errors.append("matrix identity is invalid")
    if document.get("production_acceptance") is not False:
        errors.append("repository matrix must not claim production acceptance")
    phases = document.get("phases")
    if not isinstance(phases, list) or len(phases) != len(EXPECTED):
        errors.append("matrix must contain exactly phases 0 through 6")
        return errors
    for item, expected in zip(phases, EXPECTED, strict=True):
        if not isinstance(item, dict) or set(item) != PHASE_KEYS:
            errors.append("phase schema is invalid")
            continue
        phase, scope, criterion, status = expected
        if (
            item.get("phase") != phase
            or item.get("scope") != scope
            or item.get("acceptance_criterion") != criterion
            or item.get("repository_status") != status
        ):
            errors.append(f"phase {phase} plan contract is invalid")
        if item.get("production_acceptance") is not False:
            errors.append(f"phase {phase} must not claim production acceptance")
        if not _nonempty_strings(item.get("target_evidence_required")):
            errors.append(f"phase {phase} target evidence is missing")
        missing_inputs = item.get("missing_inputs")
        if not isinstance(missing_inputs, list) or not all(
            isinstance(value, str) and value.strip() == value and bool(value)
            for value in missing_inputs
        ):
            errors.append(f"phase {phase} missing-input inventory is invalid")
    return errors


def main() -> int:
    try:
        document = load_unique_json(
            MATRIX,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("phase-acceptance-matrix-invalid", file=sys.stderr)
        return 1
    errors = matrix_errors(document)
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    print("phase-acceptance-matrix-ok phases=7 production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
