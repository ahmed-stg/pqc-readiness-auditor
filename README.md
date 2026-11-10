# PQC Readiness Auditor

A Python-based security platform for scanning cryptographic assets, assessing quantum vulnerability,
and automating remediation across certificates, TLS/SSH endpoints, network captures, source code,
and VPN gateways.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![NIST PQC / CNSA 2.0](https://img.shields.io/badge/standard-NIST%20IR%208547%20%E2%80%94%20CNSA%202.0-orange.svg)](https://csrc.nist.gov)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-1A1C2C.svg)](https://docs.astralabe.ai/ruff/)

## Overview

The PQC Readiness Auditor is designed to move beyond static certificate scanning into an active
cryptographic readiness platform with:

- **Advanced Scanning**: source code secret/crypto scanning, SSH/VPN endpoint inspection, PCAP analysis
- **Smart Risk Scoring**: Mosca's Theorem risk calculator, NIST IR 8547 and CNSA 2.0 compliance mapping, and CycloneDX CBOM export
- **Automated Remediation**: hybrid PQC certificate generation, CI gatekeeper for GitHub Actions, and an interactive FastAPI dashboard

## Unified CLI

Once installed, the tool can be used through clean commands instead of long module paths:

```bash
pqc-auditor scan-certs ./samples
pqc-auditor scan-tls example.com --port 443
pqc-auditor scan-ssh ssh.example.com
pqc-auditor scan-pcap samples/sample.pcap
pqc-auditor scan-source ./samples
pqc-auditor assess results.json --shelf-life 20 --migration-time 5
pqc-auditor report assessment.json --output report.html
pqc-auditor export-cbom results.json --output cbom.json
pqc-auditor remediate --algo ML-DSA --output hybrid-cert.pem
pqc-auditor dashboard --port 8080
```

## Capabilities

- **Advanced Scanning**: source code secret/crypto scanning, SSH/VPN endpoint inspection, PCAP analysis
- **Smart Risk Scoring**: Mosca's Theorem risk calculator, NIST/CNSA 2.0 compliance mapping, CBOM export (CycloneDX)
- **Automated Remediation**: hybrid certificate generation, CI gatekeeper for GitHub Actions/GitLab CI, interactive web dashboard (FastAPI)

## Project Structure

```text
pqc-readiness-auditor/
├── README.md
├── requirements.txt
├── pyproject.toml
├── PQC_READINESS_AUDITOR_SUMMARY.md
├── Makefile
├── Dockerfile
├── demo.py
├── .gitignore
├── .github/
│   └── workflows/
│       └── pqc-scan.yml
├── samples/
│   ├── weak_cert.pem
│   ├── weak_key.pem
│   ├── vulnerable_source.py
│   └── sample.pcap
├── src/
│   ├── __init__.py
│   ├── cli.py
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── cert_scan.py
│   │   ├── tls_scan.py
│   │   ├── ssh_scan.py
│   │   ├── pcap_scan.py
│   │   ├── source_scan.py
│   │   └── vpn_scan.py
│   ├── risk/
│   │   ├── __init__.py
│   │   ├── mosca_calculator.py
│   │   ├── compliance_mapper.py
│   │   └── scorer.py
│   ├── remediation/
│   │   ├── __init__.py
│   │   └── crypto_remediator.py
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── report_generator.py
│   │   └── cbom_exporter.py
│   ├── dashboard/
│   │   ├── __init__.py
│   │   ├── fastapi_app.py
│   │   └── static/
│   │       └── dashboard.html
│   └── ci/
│       ├── __init__.py
│       └── gatekeeper.py
└── tests/
    ├── __init__.py
    ├── test_tls_scan.py
    ├── test_mosca_calculator.py
    └── test_cli_integration.py
```

## Getting Started

### Prerequisites

- Python 3.10+
- OpenSSL 3.5+ recommended for native ML-KEM and ML-DSA support (earlier versions may require external providers)
- (Optional) Open Quantum Safe `oqs-provider` or similar for advanced PQC certificate generation

### Installation

```bash
pip install -r requirements.txt
```

Or install in development mode:

```bash
pip install -e .
```

### Quick Start

After installation, run the demo against the bundled sample assets:

```bash
python demo.py
```

Or use the unified CLI directly:

```bash
pqc-auditor scan-certs ./samples --output results.json
pqc-auditor assess results.json --shelf-life 20 --migration-time 5
pqc-auditor report assessment.json --output report.html
pqc-auditor export-cbom results.json --output cbom.json
pqc-auditor remediate --algo ML-DSA --output hybrid-cert.pem
```

## Samples

The `samples/` folder is included so the project can be tested immediately after cloning:

- `samples/weak_cert.pem` — a vulnerable RSA 2048 certificate
- `samples/weak_key.pem` — the corresponding private key
- `samples/vulnerable_source.py` — a tiny source file using `hashlib.md5`
- `samples/sample.pcap` — a small packet capture with a TLS handshake

## Demo and Visual Proof

### Terminal output

The demo prints a rich, tabular summary of each scan stage. A typical terminal output looks like this:

```text
[demo] 1) Scanning sample certificate
file: samples/weak_cert.pem        status: weak        weaknesses: rsa key too small

[demo] 2) Risk assessment
overall_score: 93.0      grade: critical      weak_assets: 1 / 2

[demo] 3) HTML report
report.html written

[demo] 4) CycloneDX CBOM export
cbom.json written

[demo] 5) Remediation (hybrid certificate generation)
hybrid_cert.pem written
```

### Dashboard

The interactive dashboard is served locally by FastAPI and includes a Chart.js risk score panel,
asset summary, and remediation planning UI:

```bash
pqc-auditor dashboard --port 8080
```

A screenshot of the dashboard can be captured from `http://localhost:8080` after startup.

## Sample Output Snippets

### Mosca Risk Calculation

For a data set with a 20-year shelf life and a 5-year migration window against a 2030 quantum
arrival estimate, the tool reports:

```text
Mosca's Theorem: X + Y > Z
20 yrs + 5 yrs > 4 yrs = CRITICAL
```

### CycloneDX CBOM Snippet

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:<uuid>",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-10T00:00:00+00:00",
    "tools": [{"name": "PQC Readiness Auditor", "version": "0.1.0"}],
    "component": {
      "type": "application",
      "name": "Scanned Environment",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "operating-system",
      "name": "weak.example.com",
      "version": "2036-11-07T21:17:12+00:00",
      "description": ["rsa key too small"],
      "purl": "pkg:generic/samples/weak_cert.pem"
    }
  ]
}
```

## DevSecOps Integration

### GitHub Actions Gatekeeper

The repository includes `.github/workflows/pqc-scan.yml`. It fails a pull request or main push when
newly introduced certificates are expired or use quantum-vulnerable algorithms.

### Docker

A lightweight container is provided for CI and local runs:

```bash
docker build -t pqc-auditor .
docker run --rm -p 8080:8080 pqc-auditor
```

### Makefile

A `Makefile` is included for common development tasks:

```bash
make install
make demo
make test
make docker-build
make docker-run
```

## Risk Model

Mosca's Theorem states that if X (data shelf-life) + Y (migration time) > Z (quantum arrival), the
data is at risk. The tool lets users tag assets by data sensitivity so high-shelf-life records can be
prioritized for remediation.

## License

MIT
