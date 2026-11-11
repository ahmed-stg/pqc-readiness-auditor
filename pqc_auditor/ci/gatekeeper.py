from __future__ import annotations

import typing

from pqc_auditor.scanner import CertScanner
from pqc_auditor.reporting import ReportGenerator


class PQCGatekeeper:
    """CI gatekeeper: scan artifacts and fail if new classically weak/expired certs are introduced."""

    def __init__(self, cert_dir: str) -> None:
        self.cert_dir = cert_dir
        self.scanner = CertScanner()

    def run(self) -> dict:
        findings = self.scanner.scan_directory(self.cert_dir)
        weak = [f for f in findings if f.get("status") in ("weak", "expired", "error")]
        report = ReportGenerator().generate_json({"findings": findings, "status": "ci_scan"})
        return {
            "passed": len(weak) == 0,
            "weak_count": len(weak),
            "total_scanned": len(findings),
            "report": report,
        }
