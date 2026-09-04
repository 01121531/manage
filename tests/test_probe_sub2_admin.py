from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from platform.sub2_admin import (
    Sub2AdminProbeResult,
    Sub2AdminRejected,
    Sub2AdminUnavailable,
)
from scripts import probe_sub2_admin


class ProbeSub2AdminCliTests(unittest.TestCase):
    def _invoke(self, side_effect):
        output = io.StringIO()
        with patch.object(
            probe_sub2_admin,
            "run_probe",
            side_effect=side_effect if isinstance(side_effect, Exception) else None,
            return_value=None if isinstance(side_effect, Exception) else side_effect,
        ), patch("sys.stdout", output):
            exit_code = probe_sub2_admin.main()
        return exit_code, output.getvalue()

    def test_success_outputs_only_boolean_status(self):
        exit_code, output = self._invoke(Sub2AdminProbeResult(True, True))

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output), {"authenticated": True, "reachable": True})

    def test_rejection_reports_reachable_without_echoing_secret(self):
        secret = "sensitive" + "-admin-key"
        exit_code, output = self._invoke(Sub2AdminRejected(secret))

        self.assertEqual(exit_code, 1)
        self.assertEqual(json.loads(output), {"authenticated": False, "reachable": True})
        self.assertNotIn(secret, output)

    def test_unavailable_reports_no_reachability_without_echoing_secret(self):
        secret = "sensitive" + "-vault-token"
        exit_code, output = self._invoke(Sub2AdminUnavailable(secret))

        self.assertEqual(exit_code, 1)
        self.assertEqual(json.loads(output), {"authenticated": False, "reachable": False})
        self.assertNotIn(secret, output)


if __name__ == "__main__":
    unittest.main()
