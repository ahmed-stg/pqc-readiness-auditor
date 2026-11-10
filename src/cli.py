from __future__ import annotations

import argparse
import sys
import typing

from src.scanner import CertScanner, TLSScanner
from src.risk import MoscaRiskCalculator, RiskScorer
from src.remediation import CryptoRemediator
from src.reporting import ReportGenerator


def main(argv: typing.Optional[typing.List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="pqc-scan", description="PQC Readiness Auditor CLI")
    sub = parser.add_subparsers(dest="command")

    cert_scan_parser = sub.add_parser("cert-scan", help="Scan certificate files")
    cert_scan_parser.add_argument("directory")
    cert_scan_parser.add_argument("--output", default=None)

    tls_parser = sub.add_parser("tls-scan", help="Scan TLS endpoint")
    tls_parser.add_argument("host")
    tls_parser.add_argument("--port", type=int, default=443)

    assess_parser = sub.add_parser("assess", help="Run risk assessment")
    assess_parser.add_argument("input_json")
    assess_parser.add_argument("--shelf-life", type=float, default=10.0)
    assess_parser.add_argument("--migration-time", type=float, default=3.0)
    assess_parser.add_argument("--output", default=None)

    report_parser = sub.add_parser("report", help="Generate HTML report")
    report_parser.add_argument("input_json")
    report_parser.add_argument("--output", default=None)

    rem_parser = sub.add_parser("remediate", help="Generate hybrid certificate")
    rem_parser.add_argument("--cn", default="pqc-remediated.example.com")
    rem_parser.add_argument("--algo", default="ML-DSA")
    rem_parser.add_argument("--output", default=None)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    if args.command == "cert-scan":
        results = CertScanner().scan_directory(args.directory)
        if args.output:
            ReportGenerator().generate_json({"findings": results}, args.output)
        else:
            print(json_dumps({"findings": results}))
        return 0

    if args.command == "tls-scan":
        result = TLSScanner().scan(args.host, ports=[args.port])
        print(json_dumps(result))
        return 0

    if args.command == "assess":
        import json as _json
        try:
            with open(args.input_json, "r", encoding="utf-8") as fh:
                payload = _json.load(fh)
        except (_json.JSONDecodeError, FileNotFoundError):
            print(f"Could not read assessment input: {args.input_json}", file=sys.stderr)
            return 2
        findings = payload.get("findings", payload if isinstance(payload, list) else [])
        assessment = RiskScorer().assess(findings, args.shelf_life, args.migration_time)
        if args.output:
            if args.output.endswith(".html"):
                ReportGenerator().generate_html(assessment, args.output)
                ReportGenerator().generate_json(assessment, args.output.replace(".html", ".json", 1))
            else:
                ReportGenerator().generate_json(assessment, args.output)
        else:
            print(json_dumps(assessment))
        return 0

    if args.command == "report":
        import json as _json
        try:
            with open(args.input_json, "r", encoding="utf-8") as fh:
                assessment = _json.load(fh)
        except (_json.JSONDecodeError, FileNotFoundError):
            print(f"Could not read report input: {args.input_json}", file=sys.stderr)
            return 2
        out = args.output or "report.html"
        ReportGenerator().generate_html(assessment, out)
        print(f"Report written to {out}")
        return 0

    if args.command == "remediate":
        result = CryptoRemediator().generate_hybrid_cert(common_name=args.cn, algorithm=args.algo, output_path=args.output)
        print(json_dumps(result))
        return 0

    parser.print_help()
    return 1


def json_dumps(obj) -> str:
    import json
    return json.dumps(obj, indent=2)


if __name__ == "__main__":
    raise SystemExit(main())
