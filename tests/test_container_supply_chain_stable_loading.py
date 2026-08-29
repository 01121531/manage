from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_container_supply_chain


FIXED_ASSET_ERROR = (
    "container-supply-chain-error: "
    "Cannot inspect container supply-chain assets\n"
)


class ContainerSupplyChainStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflows = verify_container_supply_chain.load_workflows()
        self.dockerfile_texts = tuple(
            external_text.load_stable_text(path)
            for path in verify_container_supply_chain.DOCKERFILES
        )

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_container_supply_chain.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_dockerfiles_are_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in verify_container_supply_chain.DOCKERFILES:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_container_supply_chain,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self.run_main()

        self.assertEqual(
            result,
            (
                0,
                "container-supply-chain-ok "
                "build-scan-sbom-sign-attest-release-order-validated\n",
                "",
            ),
        )
        self.assertEqual(
            [call.args for call in stable_read.call_args_list],
            [(path,) for path in verify_container_supply_chain.DOCKERFILES],
        )

    def test_each_dockerfile_accepts_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for index, source in enumerate(self.dockerfile_texts):
                with self.subTest(path=verify_container_supply_chain.DOCKERFILES[index]):
                    raw = source.encode("utf-8")
                    if not raw.endswith(b"\n"):
                        raw += b"\n"
                    prefix = raw + b"#"
                    padding = external_text.MAX_REPOSITORY_TEXT_BYTES - len(prefix)
                    self.assertGreaterEqual(padding, 0)
                    exact = prefix + b"x" * padding
                    path = Path(temporary) / f"Dockerfile-{index}"
                    path.write_bytes(exact)
                    dockerfiles = list(verify_container_supply_chain.DOCKERFILES)
                    dockerfiles[index] = path

                    with mock.patch.object(
                        verify_container_supply_chain,
                        "DOCKERFILES",
                        tuple(dockerfiles),
                    ):
                        self.assertEqual(self.run_main()[0], 0)
                        path.write_bytes(exact + b"x")
                        self.assertEqual(
                            self.run_main(),
                            (1, "", FIXED_ASSET_ERROR),
                        )

    def test_invalid_utf8_for_each_dockerfile_uses_fixed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for index in range(len(verify_container_supply_chain.DOCKERFILES)):
                with self.subTest(path=verify_container_supply_chain.DOCKERFILES[index]):
                    path = Path(temporary) / f"Dockerfile-invalid-{index}"
                    path.write_bytes(b"\xff")
                    dockerfiles = list(verify_container_supply_chain.DOCKERFILES)
                    dockerfiles[index] = path

                    with mock.patch.object(
                        verify_container_supply_chain,
                        "DOCKERFILES",
                        tuple(dockerfiles),
                    ):
                        self.assertEqual(
                            self.run_main(),
                            (1, "", FIXED_ASSET_ERROR),
                        )

    def test_link_or_reparse_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            verify_container_supply_chain,
            "load_workflows",
            return_value=self.workflows,
        ), mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, "", FIXED_ASSET_ERROR))
        open_file.assert_not_called()

    def test_stable_file_shape_failures_keep_cli_error_fixed(self) -> None:
        for reason in ("not-regular", "changed"):
            with self.subTest(reason=reason), mock.patch.object(
                verify_container_supply_chain,
                "load_stable_text",
                side_effect=external_json.StableFileError(reason),
                create=True,
            ) as stable_read:
                result = self.run_main()

            self.assertEqual(result, (1, "", FIXED_ASSET_ERROR))
            self.assertNotIn(reason, result[2])
            stable_read.assert_called_once_with(
                verify_container_supply_chain.DOCKERFILES[0]
            )

    def test_source_has_one_shared_stable_boundary_for_all_dockerfiles(
        self,
    ) -> None:
        source = Path(verify_container_supply_chain.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".read_text(", source)
        self.assertIn(
            "tuple(load_stable_text(path) for path in DOCKERFILES)",
            source,
        )


if __name__ == "__main__":
    unittest.main()
