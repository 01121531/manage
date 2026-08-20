import unittest

from platform.worker_metrics import WorkerMetrics


class WorkerMetricsTests(unittest.TestCase):
    def test_render_prometheus_exposes_worker_and_batch_counts(self) -> None:
        metrics = WorkerMetrics("mail")
        metrics.mark_heartbeat()
        metrics.record_batch({"waiting": 2, "code_ready": 1})
        text = metrics.render_prometheus()
        self.assertIn('platform_worker_info{worker="mail"} 1', text)
        self.assertIn('platform_worker_batch_results_total{worker="mail",result="code_ready"} 1', text)
        self.assertIn('platform_worker_batch_results_total{worker="mail",result="waiting"} 2', text)
        self.assertIn('platform_worker_heartbeat_timestamp_seconds{worker="mail"}', text)
        self.assertIn('platform_worker_last_batch_timestamp_seconds{worker="mail"}', text)


if __name__ == "__main__":
    unittest.main()
