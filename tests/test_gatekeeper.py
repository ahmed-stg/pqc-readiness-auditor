from __future__ import annotations

import os
import tempfile
import unittest

from pqc_auditor.ci.gatekeeper import PQCGatekeeper


class TestGatekeeper(unittest.TestCase):
    def test_passed_when_directory_has_no_certs(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = PQCGatekeeper(tmp).run()
            self.assertTrue(result["passed"])
            self.assertEqual(result["total_scanned"], 0)
            self.assertEqual(result["weak_count"], 0)

    def test_fails_when_weak_cert_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "weak_cert.pem")
            dest = os.path.join(tmp, "weak.pem")
            os.symlink(os.path.abspath(src), dest)
            result = PQCGatekeeper(tmp).run()
            self.assertFalse(result["passed"])
            self.assertGreater(result["weak_count"], 0)
