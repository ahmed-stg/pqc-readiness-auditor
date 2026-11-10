from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

SAMPLE_CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "weak_cert.pem")


class TestCLIIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

    def _run(self, args, check=True):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.abspath(self.repo_root)
        cmd = [sys.executable, "-m", "src.cli", *args]
        result = subprocess.run(cmd, cwd=os.path.abspath(self.repo_root), env=env, capture_output=True, text=True)
        if check:
            self.assertEqual(result.returncode, 0, msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        return result

    def test_cert_scan_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "scan.json")
            result = self._run(["scan-certs", os.path.dirname(SAMPLE_CERT), "--output", out])
            with open(out, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            assert data["findings"]
            assert any(f["file"].endswith("weak_cert.pem") for f in data["findings"])
            assert any(f["status"] in ("weak", "unreadable") for f in data["findings"])

    def test_assess_produces_score_and_grade(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_out = os.path.join(tmp, "scan.json")
            self._run(["scan-certs", os.path.dirname(SAMPLE_CERT), "--output", scan_out])
            assess_out = os.path.join(tmp, "assessment.json")
            result = self._run(["assess", scan_out, "--shelf-life", "10", "--migration-time", "3", "--output", assess_out])
            with open(assess_out, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            assert "overall_score" in data
            assert "grade" in data
            assert "mosca" in data
            assert "compliance" in data
            assert data["overall_score"] >= 0
            assert data["grade"] in ("critical", "high", "medium", "low")

    def test_report_generates_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_out = os.path.join(tmp, "scan.json")
            self._run(["scan-certs", os.path.dirname(SAMPLE_CERT), "--output", scan_out])
            assess_out = os.path.join(tmp, "assessment.json")
            self._run(["assess", scan_out, "--shelf-life", "10", "--migration-time", "3", "--output", assess_out])
            html_out = os.path.join(tmp, "report.html")
            result = self._run(["report", assess_out, "--output", html_out])
            assert os.path.isfile(html_out)
            with open(html_out, "r", encoding="utf-8") as fh:
                html = fh.read()
            assert "PQC Readiness Auditor Report" in html
            assert "Overall Score" in html

    def test_remediate_generates_hybrid_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "hybrid.pem")
            result = self._run(["remediate", "--cn", "demo.example.com", "--algo", "ML-DSA", "--output", out])
            data = json.loads(result.stdout)
            assert data["status"] == "generated"
            assert data["algorithm"] == "ML-DSA"
            assert os.path.isfile(out)
            with open(out, "r", encoding="utf-8") as fh:
                content = fh.read()
            assert "-----BEGIN CERTIFICATE-----" in content
            assert data["cert_path"] == out


if __name__ == "__main__":
    unittest.main()
