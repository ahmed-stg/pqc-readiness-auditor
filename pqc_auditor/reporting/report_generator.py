from __future__ import annotations

import json
import typing
import datetime
import html


class ReportGenerator:
    """Generate human-readable HTML and machine-readable JSON reports."""

    def generate_html(self, assessment: dict, output_path: typing.Optional[str] = None) -> str:
        rows = "".join(
            f"<tr><td>{html.escape(str(r.get('file', '')))}</td>"
            f"<td>{html.escape(str(r.get('status', '')))}</td>"
            f"<td>{html.escape(str(r.get('findings', r.get('weakness', []))))}</td></tr>"
            for r in assessment.get("findings", [])
        )

        summary = assessment.get("overall_score", 0)
        grade = assessment.get("grade", "unknown")

        html = f"""<html>
<head><title>PQC Readiness Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: 6px; text-align: left; }}
  th {{ background: #f2f2f2; }}
  .badge {{ padding: 4px 8px; border-radius: 4px; color: white; }}
  .critical {{ background: #c0392b; }}
  .high {{ background: #e67e22; }}
  .medium {{ background: #f1c40f; color: #333; }}
  .low {{ background: #27ae60; }}
</style></head>
<body>
<h1>PQC Readiness Auditor Report</h1>
<p>Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}</p>
<h2>Overall Score</h2>
<p>Score: {summary}/100 <span class="badge {grade}">{grade}</span></p>
<h2>Compliance</h2>
<pre>{compliance_summary(assessment)}</pre>
<h2>Asset Findings</h2>
<table><tr><th>File</th><th>Status</th><th>Weaknesses</th></tr>{rows}</table>
</body></html>"""

        if output_path:
            with open(output_path, "w") as f:
                f.write(html)
        return html

    def generate_json(self, assessment: dict, output_path: typing.Optional[str] = None) -> str:
        text = json.dumps(assessment, indent=2)
        if output_path:
            with open(output_path, "w") as f:
                f.write(text)
        return text


def compliance_summary(assessment: dict) -> str:
    comp = assessment.get("compliance", {})
    return (
        f"Standard: {comp.get('standard','')}\n"
        f"Badge: {comp.get('badge','')}\n"
        f"Compliance: {comp.get('compliance_percentage','')}%\n"
        f"Required by: {comp.get('required_year','')}\n"
    )
