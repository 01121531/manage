import unittest

from scripts.verify_phase6_evidence_outputs import (
    ROOT,
    phase6_output_contract_errors,
)


class Phase6EvidenceOutputContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.phase6 = (ROOT / "scripts" / "phase6_rehearsal.py").read_text(
            encoding="utf-8"
        )
        cls.training = (ROOT / "scripts" / "training_evidence.py").read_text(
            encoding="utf-8"
        )
        cls.policy = (ROOT / "scripts" / "backup_output_policy.py").read_text(
            encoding="utf-8"
        )

    def errors(
        self,
        *,
        phase6: str | None = None,
        training: str | None = None,
        policy: str | None = None,
    ) -> list[str]:
        return phase6_output_contract_errors(
            self.phase6 if phase6 is None else phase6,
            self.training if training is None else training,
            self.policy if policy is None else policy,
        )

    def test_repository_contract_passes(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_phase6_preflight_publish_and_no_replace_are_required(self) -> None:
        mutations = (
            self.phase6.replace(
                "            prepare_evidence_output(options.output)\n", "", 1
            ),
            self.phase6.replace(
                "        publish_write_once_file(temporary_path, destination)",
                "        os.replace(temporary_path, destination)",
                1,
            ),
            self.phase6.replace(
                "        return prepare_write_once_file(path)", "        return path", 1
            ),
            self.phase6.replace(
                "    destination = prepare_evidence_output(path)",
                "    path.unlink(missing_ok=True)\n    destination = prepare_evidence_output(path)",
                1,
            ),
            self.phase6.replace(
                "    destination = prepare_evidence_output(path)",
                "    path.parent.mkdir(parents=True, exist_ok=True)\n"
                "    destination = prepare_evidence_output(path)",
                1,
            ),
        )
        for source in mutations:
            with self.subTest():
                self.assertNotEqual(source, self.phase6)
                self.assertTrue(self.errors(phase6=source))

    def test_training_preflight_publish_and_no_output_mutation_are_required(self) -> None:
        mutations = (
            self.training.replace(
                "    destination = prepare_write_once_file(output_path)",
                "    destination = output_path",
                1,
            ),
            self.training.replace(
                "    destination = prepare_write_once_file(path)",
                "    destination = path",
                1,
            ),
            self.training.replace(
                "        publish_write_once_file(temporary_path, path)",
                "        os.replace(temporary_path, path)",
                1,
            ),
            self.training.replace(
                "    evidence = seal_evidence(_read_json(input_path))",
                "    output_path.unlink(missing_ok=True)\n"
                "    evidence = seal_evidence(_read_json(input_path))",
                1,
            ),
            self.training.replace(
                "    destination = prepare_write_once_file(path)",
                "    path.parent.mkdir(parents=True, exist_ok=True)\n"
                "    destination = prepare_write_once_file(path)",
                1,
            ),
        )
        for source in mutations:
            with self.subTest():
                self.assertNotEqual(source, self.training)
                self.assertTrue(self.errors(training=source))

    def test_shared_hardlink_commit_and_cleanup_semantics_are_required(self) -> None:
        mutations = (
            self.policy.replace(
                "    os.link(temporary_path, output_path)",
                "    os.replace(temporary_path, output_path)",
                1,
            ),
            self.policy.replace(
                "    except OSError:\n"
                "        # The hard link is the commit point.",
                "    except RuntimeError:\n"
                "        # The hard link is the commit point.",
                1,
            ),
            self.policy.replace(
                "        # reported publication failure.\n        pass\n",
                "        # reported publication failure.\n        raise\n",
                1,
            ),
        )
        for source in mutations:
            with self.subTest():
                self.assertNotEqual(source, self.policy)
                self.assertTrue(self.errors(policy=source))


if __name__ == "__main__":
    unittest.main()
