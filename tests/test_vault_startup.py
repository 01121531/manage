import unittest
from types import SimpleNamespace
from unittest import mock

from infra import mail_worker, worker


class VaultStartupTests(unittest.TestCase):
    def test_mail_worker_stops_before_metrics_or_polling_when_app_fails(self) -> None:
        with (
            mock.patch.object(
                mail_worker,
                "create_app",
                side_effect=RuntimeError("safe startup failure"),
            ),
            mock.patch.object(mail_worker, "start_worker_metrics_server") as metrics,
            mock.patch.object(mail_worker, "run_mail_worker") as run_worker,
        ):
            with self.assertRaisesRegex(RuntimeError, "safe startup failure"):
                mail_worker.main()

        metrics.assert_not_called()
        run_worker.assert_not_called()

    def test_sub2_worker_stops_before_metrics_or_claiming_when_app_fails(self) -> None:
        with (
            mock.patch.object(
                worker,
                "create_app",
                side_effect=RuntimeError("safe startup failure"),
            ),
            mock.patch.object(worker, "start_worker_metrics_server") as metrics,
            mock.patch.object(worker, "run_upload_worker") as run_worker,
        ):
            with self.assertRaisesRegex(RuntimeError, "safe startup failure"):
                worker.main()

        metrics.assert_not_called()
        run_worker.assert_not_called()

    def test_managed_sub2_worker_rejects_submit_only_runtime_before_metrics(self) -> None:
        application = SimpleNamespace(
            state=SimpleNamespace(
                settings=SimpleNamespace(environment="production")
            )
        )
        with (
            mock.patch.object(worker, "create_app", return_value=application),
            mock.patch.object(
                worker,
                "sub2_unknown_reconciliation_configured",
                return_value=False,
            ),
            mock.patch.object(worker, "start_worker_metrics_server") as metrics,
            mock.patch.object(worker, "run_upload_worker") as run_worker,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "^Sub2 unknown-result reconciliation is unavailable$",
            ):
                worker.main()

        metrics.assert_not_called()
        run_worker.assert_not_called()

    def test_sub2_worker_validates_admin_configuration_before_metrics(self) -> None:
        application = SimpleNamespace(
            state=SimpleNamespace(
                settings=SimpleNamespace(environment="production"),
                secret_resolver=object(),
            )
        )
        with (
            mock.patch.object(worker, "create_app", return_value=application),
            mock.patch.object(
                worker,
                "sub2_unknown_reconciliation_configured",
                return_value=True,
            ),
            mock.patch.object(
                worker,
                "sub2_admin_from_settings",
                side_effect=RuntimeError("Sub2 admin configuration is incomplete"),
            ) as configure_admin,
            mock.patch.object(worker, "start_worker_metrics_server") as metrics,
            mock.patch.object(worker, "run_upload_worker") as run_worker,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "^Sub2 admin configuration is incomplete$",
            ):
                worker.main()

        configure_admin.assert_called_once_with(
            application.state.settings,
            application.state.secret_resolver,
        )
        metrics.assert_not_called()
        run_worker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
