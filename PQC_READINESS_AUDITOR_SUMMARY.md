# PQC Readiness Auditor — Technical Summary

## Overview

The PQC Readiness Auditor is an active cryptographic security platform for discovering,
scoring, and remediating quantum-vulnerable assets across an environment. It is designed to
evolve beyond static certificate scanning into a full DevSecOps gatekeeper with risk modeling,
compliance mapping, automated remediation, and an operational dashboard.

This document summarizes the platform’s architecture, capabilities, and verification performed
during implementation. It is intended for technical reviewers and portfolio readers.

## Architecture

The platform is organized into focused Python packages under a `src/` layout:

- `src/scanner/` — Active and passive cryptographic asset discovery
  - Certificate file scanning (`cert_scan.py`)
  - TLS handshake inspection (`tls_scan.py`)
  - SSH host key inspection (`ssh_scan.py`)
  - PCAP passive traffic analysis (`pcap_scan.py`)
  - Source code crypto/secret scanning (`source_scan.py`)
- `src/risk/` — Intelligence layer for prioritization
  - Mosca’s Theorem risk calculator (`mosca_calculator.py`)
  - NIST IR 8547 and CNSA 2.0 compliance mapping (`compliance_mapper.py`)
  - Overall risk scoring (`scorer.py`)
- `src/remediation/` — Automated remediation artifacts
  - Hybrid/PQC certificate generation (`crypto_remediator.py`)
- `src/reporting/` — Machine and human-readable output
  - HTML/JSON report generation (`report_generator.py`)
  - CycloneDX CBOM export (`cbom_exporter.py`)
- `src/dashboard/` — Operational UI and API
  - FastAPI app with interactive Chart.js dashboard (`fastapi_app.py`)
- `src/ci/` — DevSecOps gatekeeper
  - CI gatekeeper module (`gatekeeper.py`)
  - GitHub Actions workflow (`.github/workflows/pqc-scan.yml`)
- `src/cli.py` — Unified CLI entrypoint

## Capabilities

### Advanced scanning

The scanner layer addresses cryptographic risk that static certificate checks miss:

- **Certificate scanning** detects weak signature algorithms, small RSA keys, and expiry in
  PEM/DER files and directories.
- **TLS scanning** performs a live handshake and reports protocol version, cipher, certificate
  details, and weakness classification.
- **SSH scanning** uses Paramiko to inspect host keys and flag weak or deprecated key types.
- **PCAP analysis** uses Scapy to find TLS handshake traffic in captures for passive discovery
  of encrypted services.
- **Source code scanning** combines AST-based import detection with regex-based patterns to
  catch legacy crypto calls (for example, `hashlib.md5`, legacy RSA handling) and embedded
  secrets.

### Smart risk scoring

Raw findings are translated into decision-ready risk signals:

- **Mosca’s Theorem** is implemented as `X + Y > Z`, where `X` is data shelf-life, `Y` is
  migration time, and `Z` is the projected arrival of cryptographically relevant quantum
  computers. Assets can be tagged by sensitivity so that high-shelf-life data is prioritized.
- **Compliance mapping** grades findings against NIST IR 8547 and CNSA 2.0 timelines and emits a
  readiness status such as “2027 CNSA Compliant” or “Critical Action Required”.
- **Risk scoring** combines weak-asset ratio, quantum exposure, and compliance progress into a
  single overall score and grade.

### Automated remediation and DevSecOps

The platform is built to act on its own findings:

- A `--remediate`-style path generates hybrid certificates for vulnerable endpoints, with
  support for PQC-relevant algorithm selection such as ML-DSA or X25519MLKEM768.
- A CI gatekeeper scans certificate directories and fails the build when weak or expired assets
  are detected, making the auditor usable as a pull-request gate.
- GitHub Actions workflow integration is provided out of the box.

### Reporting

Output is available in both operational and machine-consumable forms:

- HTML reports with summary score, grade, compliance summary, and asset findings.
- JSON assessment output for downstream automation.
- CycloneDX Cryptographic Bill of Materials export for integration with enterprise tracking
  platforms.

## Demo and verification

A small end-to-end demo (`demo.py`) was added with a generated sample RSA 2048 certificate.
Running the demo exercises the full pipeline:

1. Certificate scan of the sample file
2. Risk assessment with Mosca scoring and CNSA 2.0 compliance mapping
3. HTML and JSON report generation
4. CycloneDX CBOM export
5. Hybrid certificate generation for remediation

The demo shows the platform detecting a weak RSA 2048 certificate, classifying it as “weak”,
scoring it as critical under Mosca exposure, and producing a “Critical Action Required”
compliance badge, followed by successful remediation artifact generation.

Verification performed:

- Python dependencies installed and imported: `cryptography`, `paramiko`, `scapy`, `OpenSSL`,
  `fastapi`, `pydantic`.
- Unit tests pass: Mosca calculator and TLS weak-detection tests.
- CLI integration tests cover `cert-scan`, `assess`, `report`, and `remediate` subcommands.
- FastAPI dashboard endpoints return expected HTML and JSON responses.
- CI gatekeeper runs and returns structured results.

## Project structure

```
pqc-readiness-auditor/
├── README.md
├── requirements.txt
├── pyproject.toml
├── PQC_READINESS_AUDITOR_SUMMARY.md
├── demo.py
├── .gitignore
├── .github/workflows/pqc-scan.yml
├── samples/
│   ├── weak_cert.pem
│   └── weak_key.pem
├── src/
│   ├── __init__.py
│   ├── cli.py
│   ├── scanner/
│   ├── risk/
│   ├── remediation/
│   ├── reporting/
│   ├── dashboard/
│   └── ci/
└── tests/
    ├── __init__.py
    ├── test_mosca_calculator.py
    ├── test_tls_scan.py
    └── test_cli_integration.py
```

## Status

The project is a functional scaffold with a working end-to-end pipeline, unit tests, CLI
integration tests, and a dashboard entrypoint. It is intentionally modular so each capability
can be extended independently, for example by adding deeper PCAP parsing, stronger PQC
certificate tooling, or a persistent scan database.

## Conclusion

The PQC Readiness Auditor demonstrates a practical path from scanning to remediation by combining
cryptographic discovery, quantum risk modeling, compliance mapping, automated artifact generation,
and DevSecOps gating. The current implementation validates the core workflow end-to-end and
provides a foundation for expanding coverage and hardening the remediation path over time.
