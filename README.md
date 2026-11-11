# PQC Readiness Auditor

A Python-based security platform for scanning cryptographic assets, assessing quantum vulnerability, and guiding remediation across certificates, TLS/SSH endpoints, network captures, source code, and VPN gateways.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![NIST PQC / CNSA 2.0](https://img.shields.io/badge/standard-NIST%20IR%208547%20%E2%80%94%20CNSA%202.0-orange.svg)](https://csrc.nist.gov)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-1A1C2C.svg)](https://docs.astral.sh/ruff/)

## Overview

The PQC Readiness Auditor is designed to move beyond static certificate scanning into an active
cryptographic readiness platform with:

- **Advanced Scanning**: certificate scanning, TLS handshake assessment, SSH host key and key exchange inspection, passive PCAP analysis, source code secret/crypto scanning, VPN gateway scaffolding
- **Smart Risk Scoring**: Mosca's Theorem risk calculator with configurable scenarios, NIST IR 8547 and CNSA 2.0 compliance mapping, and CycloneDX 1.6 CBOM export
- **Operational Guidance**: HTML/JSON assessment reports, CycloneDX CBOM export, and a GitHub Actions gatekeeper; remediation guidance is embedded in the report rather than performed by the tool

## Unified CLI

Once installed, the tool can be used through clean commands instead of long module paths:

```bash
pqc-auditor scan-certs ./samples
pqc-auditor scan-tls example.com --port 443
pqc-auditor scan-ssh ssh.example.com
pqc-auditor scan-pcap samples/sample.pcap
pqc-auditor scan-source ./samples
pqc-auditor scan-vpn vpn.example.com
pqc-auditor assess results.json --shelf-life 20 --migration-time 5
pqc-auditor report assessment.json --output report.html
pqc-auditor export-cbom results.json --output cbom.json
pqc-auditor gatekeeper ./samples
```

## Capabilities

- **Advanced Scanning**: certificate scanning, TLS handshake assessment, SSH host key + key exchange inspection, passive PCAP analysis, source code secret/crypto scanning, VPN gateway scaffolding
- **Smart Risk Scoring**: Mosca's Theorem risk calculator with configurable scenarios, NIST IR 8547 and CNSA 2.0 compliance mapping, CBOM export in CycloneDX 1.6 crypto-asset form
- **Operational Guidance**: HTML/JSON assessment reports, CycloneDX CBOM export, and CI gatekeeper for GitHub Actions; remediation guidance is embedded in the report rather than performed by the tool

## Project Structure

```text
pqc-readiness-auditor/
├── README.md
├── LICENSE
├── requirements.txt
├── pyproject.toml
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
│   ├── sample.pcap
│   ├── inv.json
│   ├── cbom_sample_1_6.json
│   └── cbom_sample_1_5_bad.json
├── pqc_auditor/
│   ├── __init__.py
│   ├── cli.py
│   ├── inventory.py
│   ├── schema.py
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
    ├── test_cert_scan.py
    ├── test_tls_scan.py
    ├── test_mosca_calculator.py
    ├── test_compliance_mapper.py
    ├── test_gatekeeper.py
    └── test_cli_integration.py
```

## Getting Started

### Prerequisites

- Python 3.10+
- OpenSSL 3.5+ for native ML-KEM / ML-DSA support and for the bundled TLS/SSH/Crypto scans
- Network access for TLS/SSH/VPN scans, only against targets you are authorized to test

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
pqc-auditor gatekeeper ./samples
```

To override per-asset shelf life, migration time, or quantum-arrival scenario, pass an inventory file:

```bash
pqc-auditor assess results.json --inventory samples/inv.json --scenario conservative
```

## Samples

The `samples/` folder is included so the project can be tested immediately after cloning:

- `samples/weak_cert.pem` — a vulnerable RSA 2048 certificate
- `samples/weak_key.pem` — the corresponding private key (sample/test only; not for production use)
- `samples/vulnerable_source.py` — a tiny source file using `hashlib.md5`
- `samples/sample.pcap` — a small packet capture with a TLS handshake
- `samples/inv.json` — example per-asset inventory with shelf-life, migration time, and scenario overrides
- `samples/cbom_sample_1_6.json` / `samples/cbom_sample_1_5_bad.json` — example CycloneDX payloads used by the CBOM tests

## Demo output

The demo prints a rich, tabular summary of each scan stage. A typical terminal output looks like this:

```text
[demo] 1) Scanning sample certificate
file: samples/weak_cert.pem        status: weak        weaknesses: quantum-vulnerable key algorithm

[demo] 2) Risk assessment
overall_score: 93.0      grade: critical      weak_assets: 1 / 2

[demo] 3) HTML report
report.html written

[demo] 4) CycloneDX CBOM export
cbom.json written
```

### CBOM shape

The CBOM exporter now targets the CycloneDX 1.6 crypto-asset component shape, including `cryptoProperties` for algorithm, key size, and certificate validity. A representative snippet:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:<uuid>",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-10T00:00:00+00:00",
    "tools": [{"name": "PQC Readiness Auditor", "version": "0.2.0"}],
    "component": {
      "type": "application",
      "name": "Scanned Environment",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "weak.example.com",
      "version": "2036-11-07T21:17:12+00:00",
      "purl": "pkg:generic/weak.example.com",
      "cryptoProperties": {
        "algorithm": "rsa",
        "keySize": 2048,
        "signatureAlgorithm": "sha256withrsaencryption",
        "validFrom": "2026-11-10T21:17:12+00:00",
        "validTo": "2036-11-07T21:17:12+00:00"
      }
    }
  ]
}
```

## Sample output snippets

### Mosca risk calculation

The tool now computes a configurable quantum-arrival scenario and shows the margin in years, not just a single inequality. For a 20-year shelf life and a 5-year migration window against the **conservative** 2030 arrival estimate, the assessment reports:

```text
Mosca's Theorem: X + Y > Z
20 yrs + 5 yrs > 4 yrs  →  at_risk: true  (margin: -24.0 yrs)
```

For the same assets under the **optimistic** 2040 scenario, the same scanner run reports:

```text
Mosca's Theorem: X + Y > Z
20 yrs + 5 yrs > 14 yrs  →  at_risk: false  (margin: +1.0 yrs)
```


## DevSecOps integration

### GitHub Actions gatekeeper

The repository includes `.github/workflows/pqc-scan.yml`. It fails a pull request or main push when newly introduced certificates are classically weak or expired. The gatekeeper command is `pqc-auditor gatekeeper <cert-dir>`.

### Docker

A lightweight container is provided for CI and local runs:

```bash
make docker-build
make docker-run
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

## Scanner safety and operational notes

- Active TLS, SSH, and VPN scanning should be run only against targets you are authorized to test.
- Network scanners use timeouts and are intended for point-in-time assessment, not continuous probing.
- Source and PCAP scanning are passive; certificate, TLS, SSH, and VPN scanners are active and may be logged by the target.
- Sample keys and certificates in `samples/` are for testing only and should never be deployed.

## Risk model

Mosca's Theorem states that if X (data shelf-life) + Y (migration time) > Z (quantum arrival), the data is at risk.

The auditor separates three finding classes so the urgency is clear:

- **Classically weak** — MD5, SHA-1 signatures, RSA below 2048, DSA, expired certificates
- **Quantum-vulnerable** — RSA, ECDSA, ECDH, DH, and other public-key schemes whose security depends on factoring or discrete-log assumptions
- **Hybrid / PQC-ready** — deployments already negotiating post-quantum or hybrid key exchange such as X25519MLKEM768

Risk scoring is driven by per-asset inventory, not only by global CLI defaults. An `inv.json` can set `data_shelf_life_years`, `migration_time_years`, and `quantum_arrival_scenario` per asset, and the report shows the margin in years so you can prioritize the longest-lived assets first.

Because harvest-now-decrypt-later is mainly a key-exchange problem, the TLS scanner reports which groups a server negotiates and supports (for example X25519MLKEM768), and the SSH scanner checks for `mlkem768x25519` / `sntrup761x25519` in key exchange offers. Certificate signatures can be migrated later; recorded traffic cannot be re-protected.

## License

MIT — see [LICENSE](LICENSE).
