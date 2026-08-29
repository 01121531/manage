from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.compose_tls_rotation_backend import (
    ComposeRotationBackend,
    ComposeRotationBackendError,
    ComposeRotationProfile,
    RouteObserver,
    load_compose_rotation_profile,
)
from scripts.tls_rotation_evidence import rotation_plan_digest
from scripts.tls_rotation_runtime import RuntimeInstanceSnapshot


IMAGE = "registry.example.invalid/email-platform/api@sha256:" + "a" * 64


def _profile_payload() -> dict[str, object]:
    return {
        "schema_version": 3,
        "profile_kind": "compose_tls_rotation_backend",
        "live_capture_sha256": "c" * 64,
        "target_environment": "staging",
        "service": "api",
        "expected_instance_count": 1,
        "required_observers": ["edge", "prometheus"],
        "env_file_sha256": "b" * 64,
        "expected_image": IMAGE,
        "compose_kind": "base",
        "direct_probe": {
            "executor_service": "worker-sub2",
            "expected_image": IMAGE,
            "url": "https://api:8443/readyz",
            "ca_file": "/run/secrets/internal-tls/ca.crt",
            "network": "email-platform-metrics",
        },
        "route_observers": [],
        "blocked_observers": ["edge", "prometheus"],
    }


def _projection(profile: ComposeRotationProfile) -> dict[str, object]:
    return {
        "target_environment": profile.target_environment,
        "runtime_kind": "compose",
        "service": profile.service,
        "expected_instance_count": 1,
        "required_observers": list(profile.required_observers),
        "runtime_profile_sha256": profile.profile_sha256,
        "old_leaf_sha256": "1" * 64,
        "new_leaf_sha256": "2" * 64,
        "old_spki_sha256": "3" * 64,
        "new_spki_sha256": "4" * 64,
    }


class Runner:
    def __init__(self, outputs=()):
        self.outputs = list(outputs)
        self.calls = []

    def run(self, command, *, capture_output=False, input_text=None):
        self.calls.append((list(command), capture_output, input_text))
        return self.outputs.pop(0) if self.outputs else ""


class ComposeTlsRotationBackendTests(unittest.TestCase):
    def test_action_reconciliation_is_a_stable_read_only_classification(self) -> None:
        profile = ComposeRotationProfile(
            "c" * 64, "staging", "api", 1, ("edge", "prometheus"), "b" * 64,
            IMAGE, "base", "worker-sub2", IMAGE, "https://api:8443/readyz",
            "/run/secrets/internal-tls/ca.crt", "email-platform-metrics",
            (), (), "5" * 64,
        )
        backend = ComposeRotationBackend(profile, Runner())
        before = RuntimeInstanceSnapshot({
            "instance_id": "1" * 64,
            "container_id": "1" * 64,
            "started_at": "2026-08-26T00:00:00Z",
        })
        after = RuntimeInstanceSnapshot({
            "instance_id": "2" * 64,
            "container_id": "2" * 64,
            "started_at": "2026-08-27T00:00:03Z",
        })
        observation = {
            "phase": "action_reconcile_new", "observer": "direct-instance",
            "instance_id": "2" * 64, "attempt": 1,
            "expected_sha256": "2" * 64, "peer_sha256": "2" * 64,
            "tls_version": "TLSv1.3", "observed_at": "2026-08-27T00:00:04Z",
        }
        with mock.patch.object(
            backend, "snapshot", side_effect=[[after], [after]]
        ) as snapshot, mock.patch.object(
            backend, "probe_instance", return_value=observation
        ) as probe, mock.patch.object(backend, "act") as act, mock.patch.object(
            backend, "contain"
        ) as contain:
            result = backend.reconcile_action(
                [before], old_sha256="1" * 64, new_sha256="2" * 64,
                observed_at="2026-08-27T00:00:04Z",
            )
        self.assertEqual(result.result, "verified_new")
        self.assertEqual(snapshot.call_count, 2)
        probe.assert_called_once()
        act.assert_not_called()
        contain.assert_not_called()

    def test_profile_is_external_closed_and_binds_blocked_real_observers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "profile.json"
            payload = _profile_payload()
            path.write_text(json.dumps(payload), encoding="utf-8")
            profile = load_compose_rotation_profile(path)
            self.assertEqual(profile.blocked_observers, ("edge", "prometheus"))
            self.assertEqual(
                profile.profile_sha256,
                hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
            )

            for field, value in (
                ("compose_kind", "rolling"),
                ("required_observers", ["edge"]),
                ("blocked_observers", ["edge"]),
            ):
                with self.subTest(field=field):
                    changed = dict(payload)
                    changed[field] = value
                    path = Path(raw) / f"{field}.json"
                    path.write_text(json.dumps(changed), encoding="utf-8")
                    with self.assertRaises(ComposeRotationBackendError):
                        load_compose_rotation_profile(path)

    def test_blocked_observer_fails_before_any_runner_call(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "profile.json"
            path.write_text(json.dumps(_profile_payload()), encoding="utf-8")
            profile = load_compose_rotation_profile(path)
        runner = Runner()
        with self.assertRaisesRegex(ComposeRotationBackendError, "observer"):
            ComposeRotationBackend(profile, runner).preflight(_projection(profile))
        self.assertEqual(runner.calls, [])

    def test_executable_profile_pins_image_mounts_probe_action_and_stop(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            ca = directory / "ca.crt"
            cert = directory / "tls.crt"
            key = directory / "tls.key"
            for path in (ca, cert, key):
                path.write_text("fixture", encoding="utf-8")
            profile = ComposeRotationProfile(
                live_capture_sha256="c" * 64,
                target_environment="staging",
                service="keycloak",
                expected_instance_count=1,
                required_observers=("api",),
                env_file_sha256=hashlib.sha256(b"env").hexdigest(),
                expected_image=IMAGE,
                compose_kind="base",
                direct_executor="api",
                direct_executor_image=IMAGE,
                direct_url="https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
                direct_ca_file="/run/secrets/internal-tls/ca.crt",
                direct_network="email-platform-frontend",
                route_observers=(RouteObserver(
                    logical_name="api", executor_service="api",
                    expected_image=IMAGE,
                    url="https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
                    ca_file="/run/secrets/internal-tls/ca.crt",
                ),),
                blocked_observers=(),
                profile_sha256="5" * 64,
            )
            projection = _projection(profile)
            identifier = "6" * 64
            mounts = [
                {"Type": "bind", "Source": str(ca), "Destination": "/run/secrets/internal-tls/ca.crt", "RW": False},
                {"Type": "bind", "Source": str(cert), "Destination": "/run/secrets/internal-tls/tls.crt", "RW": False},
                {"Type": "bind", "Source": str(key), "Destination": "/run/secrets/internal-tls/tls.key", "RW": False},
            ]
            peer = json.dumps({"peer_sha256": "1" * 64, "tls_version": "TLSv1.3"})
            network_id = "9" * 64
            networks = json.dumps({"email-platform-frontend": {
                "IPAddress": "172.30.0.8", "NetworkID": network_id,
            }})
            snapshot = [
                identifier, identifier, "true", "2026-08-27T00:00:00Z",
                json.dumps(mounts), IMAGE, networks,
            ]
            executor = "7" * 64
            executor_snapshot = [
                executor, executor, "true", IMAGE,
                json.dumps({"email-platform-frontend": {
                    "IPAddress": "172.30.0.7", "NetworkID": network_id,
                }}),
            ]
            runner = Runner([
                IMAGE, IMAGE, IMAGE,
                *snapshot, *executor_snapshot, peer, *executor_snapshot, *snapshot,
                *snapshot,
                *snapshot, *executor_snapshot, peer, *executor_snapshot, *snapshot,
                "", "", "",
            ])
            backend = ComposeRotationBackend(profile, runner)
            env = {
                "PLATFORM_INTERNAL_CA_FILE": str(ca),
                "PLATFORM_INTERNAL_KEYCLOAK_CERT_FILE": str(cert),
                "PLATFORM_INTERNAL_KEYCLOAK_KEY_FILE": str(key),
            }
            with ExitStack() as stack:
                stack.enter_context(mock.patch(
                    "scripts.compose_tls_rotation_backend.read_stable_bytes", return_value=b"env"
                ))
                stack.enter_context(mock.patch(
                    "scripts.compose_tls_rotation_backend.evaluate_inventory", return_value=({}, 0)
                ))
                stack.enter_context(mock.patch(
                    "scripts.compose_tls_rotation_backend._load_env_file", return_value=env
                ))
                stack.enter_context(mock.patch(
                    "scripts.compose_tls_rotation_backend._current_leaf_identity",
                    return_value=("2" * 64, "4" * 64),
                ))
                backend.preflight(projection)
                instance = backend.snapshot()[0]
                observation = backend.probe_instance(
                    instance, expected_sha256="1" * 64,
                    phase="before_instance", observed_at="2026-08-27T00:00:01Z",
                )
                backend.act()
                backend.contain()
        self.assertEqual(observation["peer_sha256"], "1" * 64)
        flattened = [item for call, _, _ in runner.calls for item in call]
        self.assertNotIn("https://keycloak:8443/realms/email-platform/.well-known/openid-configuration", flattened)
        self.assertIn("--force-recreate", flattened)
        self.assertIn("stop", flattened)
        self.assertIn(executor, flattened)
        self.assertIn(["docker", "exec", "-i"], [call[:3] for call, _, _ in runner.calls])
        probe_inputs = [json.loads(input_text) for _, _, input_text in runner.calls if input_text]
        self.assertEqual(probe_inputs[-1]["connect_host"], "172.30.0.8")


if __name__ == "__main__":
    unittest.main()
