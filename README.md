# PQC Readiness Auditor

An active security platform for scanning cryptographic assets, assessing quantum vulnerability,
and automating remediation — built to evolve beyond static certificate scanning into full DevSecOps
integration.

## Capabilities

- **Advanced Scanning**: Source code secret/crypto scanning, SSH/VPN endpoint inspection, PCAP analysis
- **Smart Risk Scoring**: Mosca's Theorem risk calculator, NIST/CNSA 2.0 compliance mapping, CBOM export (CycloneDX)
- **Automated Remediation**: Hybrid certificate generation with OQS, CI gatekeeper for GitHub Actions/GitLab CI, interactive web dashboard (FastAPI)

## Project Structure

pqc-readiness-auditor/
├── README.md
├── requirements.txt
├── pyproject.toml
├── src/
│   ├── __init__.py
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── cert_scan.py
│   │   ├── tls_scan.py
│   │   ├── ssh_scan.py
│   │   ├── pcap_scan.py
│   │   └── source_scan.py
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
├── tests/
│   ├── __init__.py
│   ├── test_tls_scan.py
│   └── test_mosca_calculator.py
└── .github/
    └── workflows/
        └── pqc-scan.yml

## Getting Started

### Prerequisites

- Python 3.10+
- OpenSSL 3.0+
- (Optional) Open Quantum Safe `oqs-provider` for PQC certificate generation

### Installation

```bash
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan a directory of certificates
python -m src.scanner.cert_scan scan ./certs --output results.json

# Run TLS handshake scan against a host
python -m src.scanner.tls_scan scan example.com --port 443

# SSH host key inspection
python -m src.scanner.ssh_scan inspect ssh.example.com

# PCAP passive analysis
python -m src.scanner.pcap_scan analyze capture.pcap

# Source code cryptographic secret scan
python -m src.scanner.source_scan scan ./my-repo

# Full risk assessment with Mosca scoring
python -m src.risk.scorer assess results.json --data-shelf-life 20 --migration-time 5

# Compliance grading against NIST IR 8547 / CNSA 2.0
python -m src.risk.compliance_mapper grade results.json --standard CNSA2

# Export CBOM in CycloneDX format
python -m src.reporting.cbom_exporter export results.json --format cyclonedx --output cbom.json

# Generate hybrid PQC certificate (requires oqs-provider)
python -m src.remediation.crypto_remediator generate --algorithm ML-DSA --output hybrid-cert.pem

# Start interactive dashboard
python -m src.dashboard.fastapi_app run --port 8080
```

## DevSecOps Integration

### GitHub Actions Gatekeeper

Add `.github/workflows/pqc-scan.yml` to your repository. The gatekeeper fails the build if
newly introduced certificates are expired or use quantum-vulnerable algorithms.

### Docker

Build a lightweight container for CI:

```bash
docker build -t pqc-auditor .
docker run --rm pqc-auditor scan ./certs --output results.json
```

## Risk Model

Mosca's Theorem: If X (data shelf-life) + Y (migration time) > Z (quantum arrival), the data is
at risk. Tag assets by sensitivity to prioritize remediation.

## License

MIT
