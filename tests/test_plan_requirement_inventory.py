from __future__ import annotations

import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import scripts.external_json as external_json
from scripts import verify_plan_requirements
from scripts.verify_plan_requirements import (
    EXPECTED_IDS,
    INVENTORY,
    evidence_contract_errors,
    inventory_errors,
    main,
    seal_inventory,
)


class PlanRequirementInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))

    @staticmethod
    def _reseal(document: dict[str, object]) -> dict[str, object]:
        return seal_inventory(
            {key: value for key, value in document.items() if key != "integrity"}
        )

    def test_inventory_is_sealed_complete_and_gated(self) -> None:
        self.assertEqual(inventory_errors(self.inventory, check_files=True), [])
        self.assertEqual(
            [entry["id"] for entry in self.inventory["requirements"]],
            list(EXPECTED_IDS),
        )
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/verify_plan_requirements.py", gate)

    def test_inventory_preserves_nonproduction_boundary_and_exact_counts(self) -> None:
        self.assertFalse(self.inventory["production_acceptance"])
        self.assertEqual(self.inventory["summary"]["total"], 52)
        self.assertEqual(self.inventory["summary"]["repository_proven"], 43)
        self.assertEqual(self.inventory["summary"]["indirect_only"], 0)
        self.assertEqual(self.inventory["summary"]["missing_implementation"], 1)
        self.assertEqual(self.inventory["summary"]["external_input_required"], 3)
        self.assertEqual(self.inventory["summary"]["target_evidence_required"], 5)

    def test_closed_repository_gaps_and_nonproduction_target_boundary_are_explicit(self) -> None:
        entries = {
            entry["id"]: entry for entry in self.inventory["requirements"]
        }
        for requirement_id in ("R01.03", "R01.05"):
            with self.subTest(requirement_id=requirement_id):
                self.assertEqual(entries[requirement_id]["classification"], "repository_proven")
                self.assertIsNone(entries[requirement_id]["gap_or_boundary"])
        nonproduction = entries["R11.05"]
        self.assertEqual(
            nonproduction["classification"],
            "target_evidence_required",
        )
        self.assertIn("IAM", nonproduction["gap_or_boundary"])

    def test_chapter_nine_evidence_tracks_the_split_frontend_boundaries(self) -> None:
        entries = {
            item["id"]: item for item in self.inventory["requirements"]
            if item["chapter"] == 9
        }
        expected = {
            "R09.01": {"frontend/src/AuthenticatedShell.tsx"},
            "R09.02": {"frontend/src/views/PoliciesView.tsx"},
            "R09.03": {
                "frontend/src/App.tsx",
                "frontend/src/AuthenticatedShell.tsx",
                "frontend/src/views/DashboardView.tsx",
            },
            "R09.04": {
                "frontend/src/views/TasksView.tsx",
                "frontend/src/views/UploadsView.tsx",
                "frontend/src/authenticated.css",
            },
            "R09.05": {
                "frontend/src/AuthenticatedShell.tsx",
                "frontend/src/authenticated.css",
            },
            "R09.06": {
                "frontend/src/views/CardsView.tsx",
                "platform/api/v1/routes.py",
            },
        }
        self.assertEqual(set(entries), set(expected))
        for requirement_id, paths in expected.items():
            with self.subTest(requirement_id=requirement_id):
                expected_classification = (
                    "missing_implementation"
                    if requirement_id == "R09.06"
                    else "repository_proven"
                )
                self.assertEqual(
                    entries[requirement_id]["classification"],
                    expected_classification,
                )
                self.assertTrue(paths.issubset(set(entries[requirement_id]["evidence"])))
                self.assertIn(
                    "frontend/e2e/platform.spec.ts",
                    entries[requirement_id]["evidence"],
                )

    def test_card_pool_secure_import_remains_an_explicit_implementation_gap(self) -> None:
        entry = next(
            item for item in self.inventory["requirements"] if item["id"] == "R09.06"
        )
        self.assertEqual(entry["classification"], "missing_implementation")
        for term in (
            "Card Vault",
            "租户",
            "批次摘要",
            "数量",
            "短期一次性凭据",
            "PAN/CVV",
            "secret_ref",
            "末四位",
        ):
            self.assertIn(term, entry["requirement"])
        self.assertIn("引用清单登记", entry["gap_or_boundary"])
        self.assertIn("R05.01", entry["gap_or_boundary"])

    def test_card_allocation_closes_source_selection_rules_with_direct_evidence(self) -> None:
        entry = next(
            item for item in self.inventory["requirements"] if item["id"] == "R05.02"
        )
        self.assertEqual(entry["classification"], "repository_proven")
        for term in ("池", "地区", "品牌", "有效期", "业务规则", "分配原因"):
            self.assertIn(term, entry["requirement"])
        self.assertIsNone(entry["gap_or_boundary"])
        self.assertIn("platform/operational_policies.py", entry["evidence"])
        self.assertIn("platform/migrations/versions/0031_card_pool_routing.py", entry["evidence"])

    def test_card_vault_and_pci_scope_remain_an_external_review_boundary(self) -> None:
        entry = next(
            item for item in self.inventory["requirements"] if item["id"] == "R05.01"
        )
        self.assertEqual(entry["classification"], "external_input_required")
        self.assertIn("Card Vault", entry["requirement"])
        self.assertIn("PCI DSS", entry["requirement"])
        self.assertIn("approved", entry["gap_or_boundary"])
        self.assertIn(
            "deploy/decision-envelopes/card-pci.synthetic.json",
            entry["evidence"],
        )
        self.assertIn(
            "scripts/decision_envelope_validation.py",
            entry["evidence"],
        )

    def test_high_risk_entries_preserve_the_source_semantic_scope(self) -> None:
        entries = {item["id"]: item for item in self.inventory["requirements"]}
        required_terms = {
            "R01.02": ("EXE 输入", "日志", "崩溃报告", "API 响应"),
            "R03.02": ("退避", "过期", "取消", "防暴力"),
            "R04.04": ("完成", "超时", "注销", "设备撤销", "管理员回收", "临时内容"),
            "R05.05": ("提交", "取消", "超时", "管理员回收", "后续分配"),
            "R07.04": ("Origin", "CSP", "HSTS", "CSRF", "请求体限制", "速率限制", "登录失败锁定"),
        }
        for requirement_id, terms in required_terms.items():
            with self.subTest(requirement_id=requirement_id):
                requirement = entries[requirement_id]["requirement"]
                self.assertEqual(
                    [term for term in terms if term not in requirement],
                    [],
                )

    def test_t171_entries_preserve_the_source_semantic_scope(self) -> None:
        entries = {item["id"]: item for item in self.inventory["requirements"]}
        required_terms = {
            "R01.01": ("登录", "注销", "禁用", "设备撤销", "停止新请求"),
            "R01.04": ("账号", "代理", "分组", "并发", "模型", "客户端"),
            "R01.06": ("单组织", "tenant_id", "多团队隔离"),
            "R01.08": ("CVV", "PAN", "token", "末四位", "非敏感字段"),
            "R01.09": ("服务端连接器", "上游地址", "认证细节"),
            "R02.01": ("Web", "API", "业务服务", "异步 Worker", "密钥", "数据库", "边界层"),
            "R02.02": ("Compose", "Kubernetes", "规模", "合规"),
            "R02.03": ("Keycloak", "身份", "API", "资源权限", "Vault", "密钥", "Worker", "外部执行"),
            "R03.01": (
                "随机 code_verifier/state",
                "系统浏览器",
                "loopback",
                "authorization code",
                "PKCE",
                "短期 access_token",
                "可轮换 refresh_token",
            ),
            "R03.03": ("access token", "内存", "refresh token", "Windows 用户", "设备指纹"),
            "R03.04": ("每次请求", "用户", "设备", "角色", "会话", "资源归属", "客户端界面"),
            "R03.05": (
                "用户名",
                "组织",
                "设备名",
                "会话剩余时间",
                "锁定",
                "注销",
                "邮箱密码",
                "掩码",
                "临时揭示",
                "mailbox session",
                "queued/running/succeeded/unknown",
                "Sub2 凭据",
            ),
            "R04.01": (
                "任务类型",
                "邮箱连接器",
                "10–30 分钟",
                "opaque session_token",
                "mailbox_session_id",
                "expires_at",
                "polling_interval",
                "token hash",
            ),
            "R04.02": ("Vault", "任务开始水位", "主题/发件人过滤", "一次性消费", "消息哈希"),
            "R04.03": ("轮询", "SSE", "状态", "一次性 code", "时间", "message_id_hash", "正文", "凭据"),
        }
        for requirement_id, terms in required_terms.items():
            with self.subTest(requirement_id=requirement_id):
                requirement = entries[requirement_id]["requirement"]
                self.assertEqual(
                    [term for term in terms if term not in requirement],
                    [],
                )

    def test_upload_phase_gap_is_closed_with_runtime_evidence(self) -> None:
        missing = [
            entry
            for entry in self.inventory["requirements"]
            if entry["classification"] == "missing_implementation"
        ]
        self.assertEqual([entry["id"] for entry in missing], ["R09.06"])
        upload_phases = next(
            entry
            for entry in self.inventory["requirements"]
            if entry["id"] == "R06.02"
        )
        self.assertEqual(upload_phases["classification"], "repository_proven")
        for term in ("每一步", "结构化事件", "阶段", "错误码", "trace_id"):
            self.assertIn(term, upload_phases["requirement"])
        self.assertIsNone(upload_phases["gap_or_boundary"])
        self.assertIn(
            "platform/migrations/versions/0032_upload_phase_tracking.py",
            upload_phases["evidence"],
        )
        mail_routing = next(
            entry for entry in self.inventory["requirements"] if entry["id"] == "R04.01"
        )
        self.assertEqual(mail_routing["classification"], "repository_proven")
        mail_provider = next(
            entry for entry in self.inventory["requirements"] if entry["id"] == "R04.02"
        )
        self.assertEqual(mail_provider["classification"], "external_input_required")
        self.assertIn("received_at_or_before", mail_provider["gap_or_boundary"])
        policy = next(
            entry for entry in self.inventory["requirements"] if entry["id"] == "R09.02"
        )
        self.assertEqual(policy["classification"], "repository_proven")
        self.assertIn("platform/operational_policies.py", policy["evidence"])
        self.assertIn("platform/tests/test_migration_0028.py", policy["evidence"])

    def test_kubernetes_expansion_path_has_direct_fail_closed_evidence(self) -> None:
        entry = next(
            item for item in self.inventory["requirements"] if item["id"] == "R02.02"
        )
        self.assertEqual(entry["classification"], "repository_proven")
        self.assertIn("deploy/kubernetes/base/workloads.yaml", entry["evidence"])
        self.assertIn("scripts/verify_kubernetes_portability.py", entry["evidence"])
        self.assertIn("tests/test_kubernetes_portability.py", entry["evidence"])

    def test_repository_proven_evidence_is_minimal_direct_and_verified(self) -> None:
        proven = [
            entry
            for entry in self.inventory["requirements"]
            if entry["classification"] == "repository_proven"
        ]
        self.assertEqual(
            [entry["id"] for entry in proven if evidence_contract_errors(entry)],
            [],
        )
        self.assertLessEqual(max(len(entry["evidence"]) for entry in proven), 6)

        too_many = copy.deepcopy(proven[0])
        too_many["evidence"] = [
            "platform/models.py",
            "platform/schemas.py",
            "platform/auth.py",
            "platform/audit.py",
            "platform/lifecycle.py",
            "platform/uploads.py",
            "platform/app.py",
        ]
        verification_only = copy.deepcopy(proven[0])
        verification_only["evidence"] = [
            "tests/test_plan_requirement_inventory.py",
            "scripts/verify_plan_requirements.py",
        ]
        implementation_only = copy.deepcopy(proven[0])
        implementation_only["evidence"] = [
            "platform/models.py",
            "platform/schemas.py",
        ]
        self.assertIn("evidence is not minimal", evidence_contract_errors(too_many))
        self.assertIn(
            "direct implementation or contract evidence is missing",
            evidence_contract_errors(verification_only),
        )
        self.assertIn(
            "verification evidence is missing",
            evidence_contract_errors(implementation_only),
        )

    def test_missing_entry_reclassification_and_acceptance_escalation_fail_closed(self) -> None:
        missing = copy.deepcopy(self.inventory)
        missing["requirements"].pop()
        reclassified = copy.deepcopy(self.inventory)
        reclassified["requirements"][0]["classification"] = "target_evidence_required"
        accepted = copy.deepcopy(self.inventory)
        accepted["production_acceptance"] = True
        for document in (missing, reclassified, accepted):
            self.assertTrue(inventory_errors(self._reseal(document)))

    def test_unknown_field_stale_summary_and_tampering_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.inventory)
        unknown["approved"] = False
        stale = copy.deepcopy(self.inventory)
        stale["summary"]["repository_proven"] = 45
        tampered = copy.deepcopy(self.inventory)
        tampered["requirements"][0]["requirement"] = "shortened"
        self.assertTrue(inventory_errors(self._reseal(unknown)))
        self.assertTrue(inventory_errors(self._reseal(stale)))
        self.assertIn(
            "plan requirement inventory integrity is invalid",
            inventory_errors(tampered),
        )

    def test_cli_verifies_without_promoting_target_or_production(self) -> None:
        self.assertEqual(main(), 0)

    def test_source_document_is_read_once_through_the_stable_boundary(self) -> None:
        with mock.patch.object(
            Path,
            "read_bytes",
            side_effect=AssertionError("whole-file path read must not be used"),
        ), mock.patch.object(
            verify_plan_requirements,
            "read_stable_bytes",
            wraps=external_json.read_stable_bytes,
        ) as stable_reader:
            self.assertEqual(inventory_errors(self.inventory, check_files=True), [])

        stable_reader.assert_called_once_with(
            verify_plan_requirements.ROOT / self.inventory["source"]["path"],
            max_bytes=verify_plan_requirements.MAX_PLAN_SOURCE_BYTES,
        )

    def test_source_document_exact_limit_is_accepted_and_outside_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / self.inventory["source"]["path"]
            source.parent.mkdir(parents=True)
            gate = root / "scripts" / "quality_gate.ps1"
            gate.parent.mkdir(parents=True)
            gate.write_text(
                "python scripts/verify_plan_requirements.py\n",
                encoding="utf-8",
            )
            with mock.patch.object(
                verify_plan_requirements,
                "ROOT",
                root,
            ), mock.patch.object(
                verify_plan_requirements,
                "QUALITY_GATE",
                gate,
            ), mock.patch.object(
                verify_plan_requirements,
                "MAX_PLAN_SOURCE_BYTES",
                4,
            ):
                for raw in (b"x", b"xxxx"):
                    with self.subTest(size=len(raw)):
                        source.write_bytes(raw)
                        document = copy.deepcopy(self.inventory)
                        document["source"]["sha256"] = hashlib.sha256(raw).hexdigest()
                        errors = inventory_errors(
                            self._reseal(document),
                            check_files=True,
                        )
                        self.assertNotIn("plan source document is unavailable", errors)
                        self.assertNotIn("plan source document digest has drifted", errors)

                for raw in (b"", b"xxxxx"):
                    with self.subTest(size=len(raw)):
                        source.write_bytes(raw)
                        document = copy.deepcopy(self.inventory)
                        document["source"]["sha256"] = hashlib.sha256(raw).hexdigest()
                        errors = inventory_errors(
                            self._reseal(document),
                            check_files=True,
                        )
                        self.assertIn("plan source document is unavailable", errors)
                        self.assertNotIn("plan source document digest has drifted", errors)

    def test_source_link_or_reparse_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(
            verify_plan_requirements,
            "load_stable_text",
            return_value="python scripts/verify_plan_requirements.py",
        ), mock.patch.object(external_json.os, "open") as open_file:
            errors = inventory_errors(self.inventory, check_files=True)
        self.assertIn("plan source document is unavailable", errors)
        open_file.assert_not_called()

    def test_non_regular_open_source_is_rejected(self) -> None:
        real_fstat = os.fstat

        def non_regular_fstat(descriptor: int):
            metadata = real_fstat(descriptor)
            return SimpleNamespace(
                st_mode=stat.S_IFIFO | 0o600,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns,
                st_ctime_ns=metadata.st_ctime_ns,
                st_file_attributes=getattr(metadata, "st_file_attributes", 0),
            )

        with mock.patch.object(
            external_json.os,
            "fstat",
            side_effect=non_regular_fstat,
        ), mock.patch.object(
            verify_plan_requirements,
            "load_stable_text",
            return_value="python scripts/verify_plan_requirements.py",
        ):
            errors = inventory_errors(self.inventory, check_files=True)
        self.assertIn("plan source document is unavailable", errors)

    def test_source_read_shape_drift_is_rejected(self) -> None:
        real_fstat = os.fstat
        calls = 0

        def drifting_fstat(descriptor: int):
            nonlocal calls
            calls += 1
            metadata = real_fstat(descriptor)
            if calls == 2:
                return SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino,
                    st_nlink=metadata.st_nlink,
                    st_size=metadata.st_size + 1,
                    st_mtime_ns=metadata.st_mtime_ns,
                    st_ctime_ns=metadata.st_ctime_ns,
                    st_file_attributes=getattr(metadata, "st_file_attributes", 0),
                )
            return metadata

        with mock.patch.object(
            external_json.os,
            "fstat",
            side_effect=drifting_fstat,
        ), mock.patch.object(
            verify_plan_requirements,
            "load_stable_text",
            return_value="python scripts/verify_plan_requirements.py",
        ):
            errors = inventory_errors(self.inventory, check_files=True)
        self.assertIn("plan source document is unavailable", errors)
        self.assertEqual(calls, 2)

    def test_source_named_replacement_during_read_is_rejected(self) -> None:
        real_lstat = Path.lstat
        calls = 0

        def drifting_lstat(path: Path):
            nonlocal calls
            calls += 1
            metadata = real_lstat(path)
            if calls == 2:
                return SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino + 1,
                    st_nlink=metadata.st_nlink,
                    st_size=metadata.st_size,
                    st_mtime_ns=metadata.st_mtime_ns,
                    st_ctime_ns=metadata.st_ctime_ns,
                    st_file_attributes=getattr(metadata, "st_file_attributes", 0),
                )
            return metadata

        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=False,
        ), mock.patch.object(
            verify_plan_requirements,
            "load_stable_text",
            return_value="python scripts/verify_plan_requirements.py",
        ), mock.patch.object(Path, "lstat", drifting_lstat):
            errors = inventory_errors(self.inventory, check_files=True)
        self.assertIn("plan source document is unavailable", errors)
        self.assertEqual(calls, 2)

    def test_cli_keeps_fixed_source_error_classification(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(
            verify_plan_requirements,
            "read_stable_bytes",
            side_effect=OSError("private source path"),
        ), redirect_stderr(stderr):
            result = main()

        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue().strip(), "plan source document is unavailable")
        self.assertNotIn("private source path", stderr.getvalue())

    def test_repository_source_keeps_bounded_stable_docx_read(self) -> None:
        source = Path(verify_plan_requirements.__file__).read_text(encoding="utf-8")
        self.assertNotIn("source_path.read_bytes()", source)
        for marker in (
            "MAX_PLAN_SOURCE_BYTES = 5 * 1024 * 1024",
            "read_stable_bytes(",
            "max_bytes=MAX_PLAN_SOURCE_BYTES",
            "hashlib.sha256(source_bytes).hexdigest()",
        ):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
