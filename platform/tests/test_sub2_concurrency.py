import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock
from unittest import mock

from platform.uploads import (
    RedisSub2ConcurrencyLimiter,
    Sub2ConcurrencyBackendUnavailable,
    Sub2ConcurrencyConfigurationError,
    Sub2Policy,
)


class FakeRedisLeaseClient:
    """Small atomic store that models the limiter Lua contract."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._leases: dict[str, dict[str, int]] = {}
        self._limits: dict[str, int] = {}
        self.fail = False
        self.release_fail = False
        self.calls: list[tuple[object, ...]] = []

    def eval(self, *args: object):
        with self._lock:
            self.calls.append(args)
            if self.fail:
                raise ConnectionError("redis unavailable")
            script = str(args[0])
            leases_key = str(args[2])
            limit_key = str(args[3])
            now_ms = int(time.monotonic() * 1_000)
            leases = self._leases.setdefault(leases_key, {})
            for token, expires_at in tuple(leases.items()):
                if expires_at <= now_ms:
                    del leases[token]

            if "ZREMRANGEBYSCORE" in script:
                limit = int(args[4])
                lease_ms = int(args[5])
                token = str(args[6])
                configured = self._limits.get(limit_key)
                if configured is not None and configured != limit:
                    return [-1, 0]
                self._limits[limit_key] = limit
                if len(leases) < limit:
                    leases[token] = now_ms + lease_ms
                    return [1, 0]
                retry_ms = min(leases.values()) - now_ms
                return [0, max(retry_ms, 1)]

            if "ZSCORE" in script:
                lease_ms = int(args[4])
                token = str(args[5])
                if token not in leases:
                    return 0
                leases[token] = now_ms + lease_ms
                return 1

            if "ZREM" in script:
                if self.release_fail:
                    raise ConnectionError("release failed")
                token = str(args[4])
                removed = int(leases.pop(token, None) is not None)
                if not leases:
                    self._leases.pop(leases_key, None)
                return removed
            raise AssertionError("unexpected Lua script")


def policy(version: str = "shared-v1", concurrency: int = 1) -> Sub2Policy:
    return Sub2Policy(
        version=version,
        proxy_ref=None,
        group_id=49,
        concurrency=concurrency,
        credential_ref=None,
    )


class RedisSub2ConcurrencyLimiterTests(unittest.TestCase):
    def test_two_instances_share_one_capacity_budget(self) -> None:
        client = FakeRedisLeaseClient()
        first = RedisSub2ConcurrencyLimiter(
            "redis://unused", lease_seconds=30, client=client
        )
        second = RedisSub2ConcurrencyLimiter(
            "redis://unused", lease_seconds=30, client=client
        )
        first_entered = Event()
        second_entered = Event()
        release_first = Event()

        def hold_first() -> None:
            with first.slot("tenant-a", policy()):
                first_entered.set()
                release_first.wait(timeout=5)

        def enter_second() -> None:
            with second.slot("tenant-a", policy()):
                second_entered.set()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(hold_first)
            self.assertTrue(first_entered.wait(timeout=2))
            second_future = executor.submit(enter_second)
            self.assertFalse(second_entered.wait(timeout=0.1))
            release_first.set()
            self.assertTrue(second_entered.wait(timeout=2))
            first_future.result(timeout=2)
            second_future.result(timeout=2)

    def test_conflicting_limit_for_active_scope_fails_closed(self) -> None:
        client = FakeRedisLeaseClient()
        first = RedisSub2ConcurrencyLimiter(
            "redis://unused", lease_seconds=30, client=client
        )
        second = RedisSub2ConcurrencyLimiter(
            "redis://unused", lease_seconds=30, client=client
        )
        with first.slot("tenant-a", policy(concurrency=2)):
            with self.assertRaises(Sub2ConcurrencyConfigurationError):
                with second.slot("tenant-a", policy(concurrency=3)):
                    self.fail("an inconsistent policy must not acquire capacity")

        with self.assertRaises(Sub2ConcurrencyConfigurationError):
            with second.slot("tenant-a", policy(concurrency=3)):
                self.fail("an immutable limit must survive an idle budget")

    def test_backend_failure_does_not_grant_a_slot(self) -> None:
        client = FakeRedisLeaseClient()
        client.fail = True
        limiter = RedisSub2ConcurrencyLimiter(
            "redis://unused", lease_seconds=30, client=client
        )
        entered = False
        with self.assertRaises(Sub2ConcurrencyBackendUnavailable):
            with limiter.slot("tenant-a", policy()):
                entered = True
        self.assertFalse(entered)

    def test_release_failure_does_not_hide_known_result(self) -> None:
        client = FakeRedisLeaseClient()
        limiter = RedisSub2ConcurrencyLimiter(
            "redis://unused", lease_seconds=30, client=client
        )
        with mock.patch("platform.uploads._LOGGER.warning") as warning:
            with limiter.slot("tenant-a", policy()):
                client.release_fail = True
        warning.assert_called_once_with("Sub2 concurrency lease release failed")

    def test_live_slot_is_renewed_before_lease_expiry(self) -> None:
        client = FakeRedisLeaseClient()
        limiter = RedisSub2ConcurrencyLimiter(
            "redis://unused", lease_seconds=30, client=client
        )
        limiter._renew_interval_seconds = 0.01
        with limiter.slot("tenant-a", policy()):
            deadline = time.monotonic() + 1
            while not any("ZSCORE" in str(call[0]) for call in client.calls):
                if time.monotonic() >= deadline:
                    self.fail("the active lease was not renewed")
                time.sleep(0.005)

    def test_keys_are_hashed_and_lease_tokens_are_unique(self) -> None:
        client = FakeRedisLeaseClient()
        limiter = RedisSub2ConcurrencyLimiter(
            "redis://unused", lease_seconds=30, client=client
        )
        with limiter.slot("tenant-secret-name", policy("policy-secret-name")):
            pass
        acquire = next(call for call in client.calls if "ZREMRANGEBYSCORE" in str(call[0]))
        release = next(
            call for call in client.calls if "local removed" in str(call[0])
        )
        serialized_keys = f"{acquire[2]} {acquire[3]}"
        self.assertNotIn("tenant-secret-name", serialized_keys)
        self.assertNotIn("policy-secret-name", serialized_keys)
        self.assertEqual(acquire[6], release[4])
        self.assertEqual(len(str(acquire[6])), 32)


if __name__ == "__main__":
    unittest.main()
