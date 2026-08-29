from __future__ import annotations

import unittest

from scripts.verify_tls_rotation_executor import ROOT, validate_sources


class VerifyTlsRotationExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.executor = (ROOT / "scripts/tls_rotation_executor.py").read_text(encoding="utf-8")
        cls.runtime = (ROOT / "scripts/tls_rotation_runtime.py").read_text(encoding="utf-8")
        cls.evidence = (ROOT / "scripts/tls_rotation_evidence.py").read_text(encoding="utf-8")
        cls.cli = (ROOT / "scripts/tls_rotation_execute.py").read_text(encoding="utf-8")
        cls.runner = (ROOT / "scripts/tls_rotation_runner.py").read_text(encoding="utf-8")
        cls.compose = (ROOT / "scripts/compose_tls_rotation_backend.py").read_text(encoding="utf-8")
        cls.kubernetes = (ROOT / "scripts/kubernetes_tls_rotation_backend.py").read_text(encoding="utf-8")
        cls.materialization = (ROOT / "scripts/private_secret_materialization.py").read_text(encoding="utf-8")
        cls.residue = (ROOT / "scripts/private_secret_residue.py").read_text(encoding="utf-8")

    def validate(self, *, executor=None, runtime=None, evidence=None, cli=None, runner=None, compose=None, kubernetes=None, materialization=None, residue=None):
        return validate_sources(
            executor if executor is not None else self.executor,
            runtime if runtime is not None else self.runtime,
            evidence if evidence is not None else self.evidence,
            cli if cli is not None else self.cli,
            runner if runner is not None else self.runner,
            compose if compose is not None else self.compose,
            kubernetes if kubernetes is not None else self.kubernetes,
            materialization if materialization is not None else self.materialization,
            residue if residue is not None else self.residue,
        )

    def assert_mutation_fails(self, **sources) -> None:
        self.assertTrue(
            self.validate(**sources)
        )

    def test_current_contract_passes(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_order_and_final_recheck_mutations_fail(self) -> None:
        self.assert_mutation_fails(executor=self.executor.replace(
            "final_second = list(backend.snapshot())", "final_second = final_first", 1
        ))
        self.assert_mutation_fails(executor=self.executor.replace(
            'action["requested_at"] = clock()',
            'action["requested_at"] = action["completed_at"]', 1
        ))
        self.assert_mutation_fails(executor=self.executor.replace(
            "hmac.compare_digest(", "hmac.compare_digest_removed(", 1
        ))
        self.assert_mutation_fails(executor=self.executor.replace(
            "self.backend.close()", "pass", 1
        ))
        self.assert_mutation_fails(executor=self.executor.replace(
            "def close(self) -> None: ...", "", 1
        ))
        self.assert_mutation_fails(executor=self.executor.replace(
            "if backend is not None:\n            raise", "if False:\n            raise", 1
        ))

    def test_runtime_revision_owner_and_containment_mutations_fail(self) -> None:
        self.assert_mutation_fails(runtime=self.runtime.replace(
            'f"--revision={revision}"', '"--watch=true"', 1
        ))
        self.assert_mutation_fails(runtime=self.runtime.replace(
            'replica_metadata.get("uid") != replica_owner["uid"]', "False", 1
        ))
        self.assert_mutation_fails(executor=self.executor.replace(
            '"kubernetes_rollout_pause"', '"none"', 1
        ))

    def test_evidence_timing_and_readback_mutations_fail(self) -> None:
        self.assert_mutation_fails(evidence=self.evidence.replace(
            "old peer observation followed rotation action", "timing failure", 1
        ))
        self.assert_mutation_fails(evidence=self.evidence.replace(
            "verify_evidence(destination)", "sealed", 1
        ))

    def test_cli_runner_and_backend_boundary_mutations_fail(self) -> None:
        self.assert_mutation_fails(cli=self.cli.replace(
            '"kubernetes": build_kubernetes_rotation_backend', '"kubernetes": None', 1
        ))
        self.assert_mutation_fails(runner=self.runner.replace("shell=False", "shell=True", 1))
        self.assert_mutation_fails(compose=self.compose.replace(
            '"config", "--images"', '"config", "--services"', 1
        ))
        self.assert_mutation_fails(compose=self.compose.replace(
            "def close(self) -> None:", "def cleanup_removed(self) -> None:", 1
        ))
        self.assert_mutation_fails(kubernetes=self.kubernetes.replace(
            "revision=discovered.revision", "revision=before.revision", 1
        ))

    def test_reconcile_helper_and_exact_container_mutations_fail(self) -> None:
        self.assert_mutation_fails(kubernetes=self.kubernetes.replace(
            "    ) -> tuple[list[RuntimeInstanceSnapshot], str]:\n        snapshots = collect_kubernetes_generation(",
            "    ) -> tuple[list[RuntimeInstanceSnapshot], str]:\n        restart_kubernetes_deployment(self.runner, self._prefix, deployment=self.profile.service)\n        snapshots = collect_kubernetes_generation(",
            1,
        ))
        self.assert_mutation_fails(runtime=self.runtime.replace(
            '    """Classify normal rolling intermediates without accepting them as ready."""\n\n    deployment = _name(deployment, "Kubernetes Deployment")',
            '    """Classify normal rolling intermediates without accepting them as ready."""\n\n    runner.run([*kubectl_prefix, "delete", "pods"])\n    deployment = _name(deployment, "Kubernetes Deployment")',
            1,
        ))
        self.assert_mutation_fails(compose=self.compose.replace(
            "docker_probe_command(", "compose_probe_command(", 1
        ))
        self.assert_mutation_fails(runtime=self.runtime.replace(
            "expected_network_identity", "ignored_network_identity", 1
        ))

    def test_materialized_kubeconfig_boundary_mutations_fail(self) -> None:
        self.assert_mutation_fails(kubernetes=self.kubernetes.replace(
            "self._materialized.path", "self.profile.kubeconfig_path", 1
        ))
        self.assert_mutation_fails(kubernetes=self.kubernetes.replace(
            "self._materialized = materialize_private_secret_bytes(",
            "self._materialized = unchecked_materialization(",
            1,
        ))
        self.assert_mutation_fails(materialization=self.materialization.replace(
            "_CREATE_NEW = 1", "_CREATE_NEW = 2", 1
        ))
        self.assert_mutation_fails(materialization=self.materialization.replace(
            "os.fchmod(writer_fd, 0o400)", "pass", 1
        ))
        self.assert_mutation_fails(materialization=self.materialization.replace(
            "path.resolve(strict=False).relative_to(_REPOSITORY_ROOT.resolve(strict=True))",
            "path.absolute().relative_to(_REPOSITORY_ROOT)",
            1,
        ))
        self.assert_mutation_fails(
            materialization="import tempfile\n" + self.materialization
        )

    def test_private_residue_asset_has_a_strict_load_limit(self) -> None:
        verifier = (ROOT / "scripts/verify_tls_rotation_executor.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("PRIVATE_RESIDUE_MAX_BYTES = 64 * 1024", verifier)
        self.assertIn(
            "load_stable_text(PRIVATE_RESIDUE, max_bytes=PRIVATE_RESIDUE_MAX_BYTES)",
            verifier,
        )
        self.assertLessEqual(
            (ROOT / "scripts/private_secret_residue.py").stat().st_size,
            64 * 1024,
        )

    def test_private_residue_identity_claim_and_lease_mutations_fail(self) -> None:
        mutations = (
            self.residue.replace(
                "materialization._posix_runtime_root(create=False)",
                "materialization._posix_temp_root()",
                1,
            ),
            self.residue.replace(
                "materialization._validate_windows_base(root.parent)", "pass", 1
            ),
            self.residue.replace(
                "materialization._identity(metadata) != materialization._identity(named)",
                "False",
                1,
            ),
            self.residue.replace(
                "_load_claim(claim_bytes, claim_id)",
                "unchecked_claim(claim_bytes)",
            ),
            self.residue.replace(
                "fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)",
                "fcntl.flock(lease_fd, fcntl.LOCK_SH)",
            ),
            self.residue.replace(
                "os.open(claim_id, flags, dir_fd=root_fd)",
                "os.open(root / claim_id, flags)",
            ),
        )
        for mutation in mutations:
            with self.subTest():
                self.assert_mutation_fails(residue=mutation)

    def test_private_residue_exact_entry_and_delete_mutations_fail(self) -> None:
        mutations = (
            self.residue.replace(
                "set(os.listdir(directory_fd)) != _EXPECTED_ENTRY_NAMES",
                "False",
                1,
            ),
            self.residue.replace(
                "{entry.name for entry in directory_path.iterdir()} != _EXPECTED_ENTRY_NAMES",
                "False",
                1,
            ),
            self.residue.replace(
                "materialization._mark_windows_delete(handle)",
                "materialization._KERNEL32.DeleteFileW(str(directory_path))",
                1,
            ),
            self.residue.replace(
                "os.rmdir(claim_id, dir_fd=root_fd)",
                "os.removedirs(root / claim_id)",
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest():
                self.assert_mutation_fails(residue=mutation)

    def test_private_residue_publication_and_approval_mutations_fail(self) -> None:
        mutations = (
            self.residue.replace(
                "prepare_write_once_file(path)",
                "unchecked_prepare(path)",
                1,
            ) + "\n# prepare_write_once_file(path)\n",
            self.residue.replace(
                "write_fsynced_temporary_bytes(destination, raw)",
                "unchecked_write(destination, raw)",
                1,
            ) + "\n# write_fsynced_temporary_bytes(destination, raw)\n",
            self.residue.replace(
                "publish_write_once_file(temporary, destination)",
                "unchecked_publish(temporary, destination)",
                1,
            ) + "\n# publish_write_once_file(temporary, destination)\n",
            self.residue.replace(
                "discard_claimed_temporary_file(temporary)",
                "unchecked_discard(temporary)",
                1,
            ) + "\n# discard_claimed_temporary_file(temporary)\n",
            self.residue.replace(
                "parent_handle, parent_identity = _open_output_parent(path)",
                "parent_handle, parent_identity = unchecked_parent(path)",
                1,
            ),
            self.residue.replace(
                "_verify_output_parent(path, parent_handle, parent_identity)",
                "pass",
                1,
            ),
            self.residue.replace(
                "or materialization._identity(opened) != materialization._identity(named)",
                "or False",
                1,
            ),
            self.residue.replace(
                "materialization._identity(named) != identity",
                "False",
                1,
            ),
            self.residue.replace(
                "materialization._win_identity(named, directory=True) != identity",
                "False",
                1,
            ),
            self.residue.replace(
                "os.fsync(handle)",
                "pass",
                1,
            ) + "\n# os.O_EXCL\n# os.fsync(descriptor)\n",
            self.residue.replace(
                "read_stable_bytes(path, max_bytes=_INVENTORY_MAX_BYTES)",
                "raw",
                1,
            ),
            self.residue.replace(
                "verified = _read_inventory(output, payload_sha256)",
                "verified = json.loads(raw)",
                1,
            ),
            self.residue.replace(
                "materialization._canonical_json(verified), raw", "raw, raw", 1
            ),
            self.residue.replace("with release_control_lock():", "with nullcontext():", 1),
            self.residue.replace("if len(matches) != 1", "if not matches", 1),
            self.residue.replace(
                "_read_inventory(inventory, expected_payload_sha256)",
                "_read_inventory(inventory, document_sha256)",
                1,
            ),
            self.residue.replace(
                "hmac.compare_digest(approval, confirmation)",
                "approval == confirmation",
            ),
            self.residue.replace(
                "            publish_write_once_file(temporary, destination)\n",
                "            publish_write_once_file(temporary, destination)\n"
                "            path.unlink()\n",
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest():
                self.assert_mutation_fails(residue=mutation)

    def test_private_residue_cli_and_projection_mutations_fail(self) -> None:
        for flag in (
            'cleanup.add_argument("--inventory", required=True, type=Path)',
            'cleanup.add_argument("--expected-payload-sha256", required=True)',
            'cleanup.add_argument("--claim-id", required=True)',
            'cleanup.add_argument("--confirm-residue-cleanup", action="store_true")',
        ):
            with self.subTest(flag=flag):
                self.assert_mutation_fails(residue=self.residue.replace(flag, "pass", 1))
        self.assert_mutation_fails(
            residue=self.residue.replace(
                "            cleanup_private_secret_residue_from_inventory(\n",
                "            cleanup_private_secret_residue(\n",
                1,
            )
        )
        self.assert_mutation_fails(
            residue=self.residue.replace(
                "def _cleanup_private_secret_residue(\n",
                "def cleanup_private_secret_residue(\n",
                1,
            )
        )
        projection = 'result = {"claim_id": claim_id, "state": state}'
        for field in ("source", "secret", "path"):
            with self.subTest(field=field):
                self.assert_mutation_fails(
                    residue=self.residue.replace(
                        projection,
                        projection + f'\n        result["{field}"] = "private"',
                        1,
                    )
                )

    def test_private_residue_bulk_and_heuristic_mutations_fail(self) -> None:
        mutations = (
            self.residue + "\nPath('.').glob('*')\n",
            self.residue + "\nimport shutil\nshutil.rmtree('residue')\n",
            self.residue + "\nos.getpid()\n",
            self.residue + "\nos.stat('.').st_mtime\n",
            self.residue.replace(
                'cleanup.add_argument("--confirm-residue-cleanup", action="store_true")',
                'cleanup.add_argument("--confirm-residue-cleanup", action="store_true")\n'
                '    cleanup.add_argument("--all", action="store_true")',
                1,
            ),
            self.residue + "\nDeleteFileW('residue')\n",
        )
        for mutation in mutations:
            with self.subTest():
                self.assert_mutation_fails(residue=mutation)


if __name__ == "__main__":
    unittest.main()
