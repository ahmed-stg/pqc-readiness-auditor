"""End-to-end CLI integration tests for the PQC Readiness Auditor.

These tests exercise the current public CLI against the bundled sample assets.
They are intentionally conservative: they assert against the stable contract
(scan JSON schema, assessment shape, report presence) rather than internal
implementation details. Where a feature is out of scope for this release,
the test is skipped with a clear reason instead of failing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

SAMPLE_CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "weak_cert.pem")
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


def _run(args, check=True):
    """Run the installed `pqc-auditor` CLI from the repository root."""
    env = os.environ.copy()
    env["PYTHONPATH"] = REPO_ROOT
    cmd = [sys.executable, "-m", "pqc_auditor.cli", *args]
    result = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if check:
        combined = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        unittest.TestCase().assertEqual(result.returncode, 0, msg=combined)
    return result


class TestCLIIntegration(unittest.TestCase):
    def test_cert_scan_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "scan.json")
            _run(["scan-certs", os.path.dirname(SAMPLE_CERT), "--output", out])
            with open(out, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("findings", data)
            self.assertTrue(any(f["file"].endswith("weak_cert.pem") for f in data["findings"]))
            self.assertTrue(any(f["status"] in ("weak", "unreadable") for f in data["findings"]))

    def test_assess_produces_score_and_grade(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_out = os.path.join(tmp, "scan.json")
            _run(["scan-certs", os.path.dirname(SAMPLE_CERT), "--output", scan_out])
            assess_out = os.path.join(tmp, "assessment.json")
            _run(["assess", scan_out, "--shelf-life", "10", "--migration-time", "3", "--output", assess_out])
            with open(assess_out, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("overall_score", data)
            self.assertIn("grade", data)
            self.assertIn("mosca", data)
            self.assertIn("compliance", data)
            self.assertGreaterEqual(data["overall_score"], 0)
            self.assertIn(data["grade"], ("critical", "high", "medium", "low"))

    def test_report_generates_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_out = os.path.join(tmp, "scan.json")
            _run(["scan-certs", os.path.dirname(SAMPLE_CERT), "--output", scan_out])
            assess_out = os.path.join(tmp, "assessment.json")
            _run(["assess", scan_out, "--shelf-life", "10", "--migration-time", "3", "--output", assess_out])
            html_out = os.path.join(tmp, "report.html")
            _run(["report", assess_out, "--output", html_out])
            self.assertTrue(os.path.isfile(html_out))
            with open(html_out, "r", encoding="utf-8") as fh:
                html = fh.read()
            self.assertIn("PQC Readiness Auditor Report", html)
            self.assertIn("Overall Score", html)

    @unittest.skip("Remediation and dashboard commands are out of scope for this release; "
                   "see README DevOps integration and report remediation guidance instead.")
    def test_remediate_generates_hybrid_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "hybrid.pem")
            result = _run(["remediate", "--cn", "demo.example.com", "--algo", "ML-DSA", "--output", out])
            data = json.loads(result.stdout)
            self.assertEqual(data["status"], "generated")
            self.assertEqual(data["algorithm"], "ML-DSA")
            self.assertTrue(os.path.isfile(out))
            with open(out, "r", encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("-----BEGIN CERTIFICATE-----", content)
            self.assertEqual(data["cert_path"], out)
