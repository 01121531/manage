import unittest
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


if __name__ == "__main__":
    unittest.main()
