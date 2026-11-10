from __future__ import annotations

import json
import os
import sys
import tempfile
from typing import Optional

import typer

from src.scanner import CertScanner, TLSScanner, SSHScanner, PCAPScanner, SourceScanner, VPNScanner
from src.risk import RiskScorer
from src.remediation import CryptoRemediator
from src.reporting import ReportGenerator
from src.reporting.cbom_exporter import CBOMExporter
from src.dashboard.fastapi_app import create_app
from src import __version__

app = typer.Typer(name="pqc-auditor", help="PQC Readiness Auditor CLI")
app.version = __version__


@app.command()
def scan_certs(
    directory: str = typer.Argument(..., help="Directory containing certificate files"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Optional JSON output path"),
) -> None:
    """Scan certificate files in a directory."""
    findings = CertScanner().scan_directory(directory)
    payload = {"findings": findings, "status": "cert_scan"}
    if output:
        ReportGenerator().generate_json(payload, output)
        typer.echo(f"Results written to {output}")
    else:
        typer.echo(json.dumps(payload, indent=2))


@app.command()
def scan_tls(
    host: str = typer.Argument(..., help="Host to scan"),
    port: int = typer.Option(443, "--port", "-p", help="Port to scan"),
) -> None:
    """Perform a TLS handshake scan against a host."""
    result = TLSScanner().scan(host, ports=[port])
    typer.echo(json.dumps(result, indent=2))


@app.command()
def scan_ssh(
    host: str = typer.Argument(..., help="SSH host"),
    port: int = typer.Option(22, "--port", "-p", help="SSH port"),
) -> None:
    """Inspect SSH host keys."""
    result = SSHScanner().inspect(host, port=port)
    typer.echo(json.dumps(result, indent=2))


@app.command()
def scan_pcap(
    path: str = typer.Argument(..., help="PCAP file to analyze"),
) -> None:
    """Analyze a PCAP file for TLS handshake traffic."""
    result = PCAPScanner().analyze(path)
    typer.echo(json.dumps(result, indent=2))


@app.command()
def scan_source(
    path: str = typer.Argument(..., help="Source directory to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Optional JSON output path"),
) -> None:
    """Scan source code for weak crypto calls and secrets."""
    result = SourceScanner().scan(path)
    payload = {"path": path, **result, "status": "source_scan"}
    if output:
        ReportGenerator().generate_json(payload, output)
        typer.echo(f"Results written to {output}")
    else:
        typer.echo(json.dumps(payload, indent=2))


@app.command()
def scan_vpn(
    host: str = typer.Argument(..., help="VPN gateway host"),
    port: int = typer.Option(443, "--port", "-p", help="Port"),
) -> None:
    """Inspect a VPN gateway endpoint (scaffolded)."""
    result = VPNScanner().inspect(host, port=port)
    typer.echo(json.dumps(result, indent=2))


@app.command()
def assess(
    input_json: str = typer.Argument(..., help="Path to JSON scan results"),
    shelf_life: float = typer.Option(10.0, "--shelf-life", help="Data shelf life in years"),
    migration_time: float = typer.Option(3.0, "--migration-time", help="Migration time in years"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Optional output path"),
) -> None:
    """Run a risk assessment and compliance grading."""
    try:
        with open(input_json, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        typer.echo(f"Could not read input: {input_json} ({e})", err=True)
        raise typer.Exit(code=2)

    findings = payload.get("findings", payload if isinstance(payload, list) else [])
    assessment = RiskScorer().assess(findings, data_shelf_life_years=shelf_life, migration_time_years=migration_time)

    if output:
        if output.endswith(".html"):
            ReportGenerator().generate_html(assessment, output)
            ReportGenerator().generate_json(assessment, output.replace(".html", ".json", 1))
            typer.echo(f"HTML report written to {output}")
        else:
            ReportGenerator().generate_json(assessment, output)
            typer.echo(f"JSON assessment written to {output}")
    else:
        typer.echo(json.dumps(assessment, indent=2))


@app.command()
def report(
    input_json: str = typer.Argument(..., help="Path to JSON assessment"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="HTML report path"),
) -> None:
    """Generate an HTML report from an assessment JSON."""
    try:
        with open(input_json, "r", encoding="utf-8") as fh:
            assessment = json.load(fh)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        typer.echo(f"Could not read input: {input_json} ({e})", err=True)
        raise typer.Exit(code=2)

    out = output or "report.html"
    ReportGenerator().generate_html(assessment, out)
    typer.echo(f"Report written to {out}")


@app.command()
def export_cbom(
    input_json: str = typer.Argument(..., help="Path to JSON scan results"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="CBOM output path"),
) -> None:
    """Export findings as a CycloneDX Cryptographic Bill of Materials."""
    try:
        with open(input_json, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        typer.echo(f"Could not read input: {input_json} ({e})", err=True)
        raise typer.Exit(code=2)

    findings = payload.get("findings", payload if isinstance(payload, list) else [])
    bom = CBOMExporter().export(findings)
    out = output or "cbom.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
    typer.echo(f"CBOM written to {out}")


@app.command()
def remediate(
    cn: str = typer.Option("pqc-remediated.example.com", "--cn", help="Common name for the certificate"),
    algo: str = typer.Option("ML-DSA", "--algo", help="PQC algorithm identifier"),
    validity_days: int = typer.Option(365, "--validity-days", help="Certificate validity in days"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output PEM path"),
) -> None:
    """Generate a hybrid/PQC-ready certificate for remediation."""
    result = CryptoRemediator().generate_hybrid_cert(
        common_name=cn,
        algorithm=algo,
        validity_days=validity_days,
        output_path=output,
    )
    if "error" in result:
        typer.echo(result["error"], err=True)
        raise typer.Exit(code=1)
    typer.echo(json.dumps(result, indent=2))


@app.command()
def dashboard(port: int = typer.Option(8080, "--port", "-p", help="Port for the dashboard")) -> None:
    """Start the interactive local dashboard."""
    application = create_app()
    import uvicorn
    uvicorn.run(application, host="0.0.0.0", port=port)


@app.command()
def gatekeeper(cert_dir: str = typer.Argument(..., help="Certificate directory to scan in CI")) -> None:
    """Run the CI gatekeeper and fail if weak/expired certs are found."""
    from src.ci import PQCGatekeeper
    result = PQCGatekeeper(cert_dir).run()
    typer.echo(json.dumps(result, indent=2))
    if not result["passed"]:
        typer.echo("PQC readiness check failed: weak or expired certificates detected.", err=True)
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
