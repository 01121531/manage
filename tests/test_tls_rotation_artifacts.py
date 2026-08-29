from __future__ import annotations

from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.tls_rotation_assessment import main as assessment_main
from scripts.tls_rotation_profile import main as profile_main, review_profile, verify_profile
from scripts.tls_rotation_profile_capture import capture_profile, load_capture
from scripts.tls_rotation_support import derive_runtime_state, load_support
from scripts.tls_rotation_evidence import load_projection, verify_evidence
from tests.test_compose_tls_rotation_backend import _profile_payload


def _request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "request_kind": "tls_rotation_profile_capture_request",
        "runtime_kind": "compose",
        "target_environment": "staging",
        "service": "api",
    }


def _provider(_request_value):
    candidate = _profile_payload()
    del candidate["live_capture_sha256"]
    return candidate, {
        "instances": [{
            "instance_id": "1" * 64,
            "container_id": "2" * 64,
            "started_at": "2026-08-27T00:00:00Z",
        }],
        "captured_observers": ["direct-instance"],
        "blocked_observers": ["edge", "prometheus"],
    }


class TlsRotationArtifactTests(unittest.TestCase):
    def test_live_capture_review_is_write_once_digest_bound_and_loader_equivalent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            request = root / "request.json"
            capture = root / "capture.json"
            output = root / "profile.json"
            request.write_text(json.dumps(_request()), encoding="utf-8")
            with mock.patch(
                "scripts.tls_rotation_profile_capture.release_control_lock",
                return_value=nullcontext(),
            ):
                capture_digest = capture_profile(
                    request, capture, provider=_provider,
                    clock=lambda: "2026-08-27T00:00:01Z",
                )
            self.assertEqual(
                load_capture(capture)["integrity"]["payload_sha256"], capture_digest
            )
            with mock.patch(
                "scripts.tls_rotation_profile.release_control_lock",
                return_value=nullcontext(),
            ):
                runtime, schema, generated = review_profile(
                    request, capture, output,
                    confirm_live_capture_sha256=capture_digest,
                )
            self.assertEqual((runtime, schema), ("compose", 3))
            self.assertEqual(verify_profile("compose", output), (3, generated))
            self.assertEqual(
                json.loads(output.read_text())["live_capture_sha256"], capture_digest
            )
            with self.assertRaises(ValueError):
                review_profile(
                    request, capture, root / "second.json",
                    confirm_live_capture_sha256="0" * 64,
                )
            with self.assertRaises(ValueError):
                capture_profile(request, capture, provider=_provider)

    def test_duplicate_request_fails_without_capture_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            request = root / "request.json"
            output = root / "capture.json"
            request.write_text(
                '{"schema_version":1,"schema_version":1}', encoding="utf-8"
            )
            with mock.patch(
                "scripts.tls_rotation_profile_capture.release_control_lock",
                return_value=nullcontext(),
            ), self.assertRaises(ValueError):
                capture_profile(request, output, provider=_provider)
            self.assertFalse(output.exists())

    def test_support_and_assessment_are_derived_from_actual_entities(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            from tests.test_tls_rotation_handoff import TlsRotationHandoffTests

            values = TlsRotationHandoffTests()._inputs(root)
            projection = load_projection(values[1])
            evidence = verify_evidence(values[-1])
            support = load_support(values[3], projection, evidence)
            self.assertEqual(derive_runtime_state(evidence, projection), ("verified_new", None))
            self.assertEqual(support["derived_runtime_state"], "verified_new")
            assessment = json.loads(values[4].read_text())
            self.assertEqual(assessment["runtime_state"], "verified_new")
            self.assertNotEqual(
                assessment["assessor_reference"], assessment["reviewer_reference"]
            )
            self.assertEqual(
                assessment["supporting_evidence_sha256"],
                support["integrity"]["payload_sha256"],
            )

    def test_cli_output_is_fixed_and_invalid_input_is_redacted(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = profile_main(["review"])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "tls-rotation-profile-failed\n")
        invalid = io.StringIO()
        with redirect_stderr(invalid):
            code = assessment_main(["verify"])
        self.assertEqual(code, 1)
        self.assertEqual(invalid.getvalue(), "tls-rotation-assessment-failed\n")


if __name__ == "__main__":
    unittest.main()
