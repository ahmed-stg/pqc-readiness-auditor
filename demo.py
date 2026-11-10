#!/usr/bin/env python3
"""End-to-end demo for the PQC Readiness Auditor.

Usage:
    python demo.py
"""

from __future__ import annotations

import json
import os
import tempfile

from src.scanner import CertScanner
from src.risk import RiskScorer
from src.reporting import ReportGenerator
from src.reporting.cbom_exporter import CBOMExporter
from src.remediation import CryptoRemediator


def main() -> int:
    repo_root = os.path.dirname(os.path.abspath(__file__))
    sample_dir = os.path.join(repo_root, "samples")
    sample_cert = os.path.join(sample_dir, "weak_cert.pem")

    if not os.path.isfile(sample_cert):
        print(f"[demo] sample certificate not found at {sample_cert}")
        return 2

    print("[demo] 1) Scanning sample certificate")
    scanner = CertScanner()
    findings = [scanner.scan_file(sample_cert)]
    print(json.dumps(findings, indent=2))

    print("[demo] 2) Risk assessment")
    assessment = RiskScorer().assess(findings, data_shelf_life_years=10, migration_time_years=3)
    print(json.dumps(assessment, indent=2))

    print("[demo] 3) HTML report")
    with tempfile.TemporaryDirectory() as tmp:
        html_path = os.path.join(tmp, "report.html")
        json_path = os.path.join(tmp, "assessment.json")
        ReportGenerator().generate_html(assessment, html_path)
        ReportGenerator().generate_json(assessment, json_path)
        print(f"[demo] HTML report -> {html_path}")
        print(f"[demo] JSON assessment -> {json_path}")
        assert os.path.isfile(html_path)
        assert os.path.isfile(json_path)

        print("[demo] 4) CycloneDX CBOM export")
        bom_path = os.path.join(tmp, "cbom.json")
        bom = CBOMExporter().export(findings, output_path=bom_path)
        assert bom["bomFormat"] == "CycloneDX"
        print(f"[demo] CBOM -> {bom_path}")

        print("[demo] 5) Remediation (hybrid certificate generation)")
        rem = CryptoRemediator().generate_hybrid_cert(
            common_name="pqc-remediated.example.com",
            algorithm="ML-DSA",
            validity_days=1,
            output_path=os.path.join(tmp, "hybrid_cert.pem"),
        )
        assert rem["status"] == "generated"
        assert os.path.isfile(os.path.join(tmp, "hybrid_cert.pem"))
        print(f"[demo] hybrid cert -> {rem['cert_path']}")

    print("[demo] End-to-end demo completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
