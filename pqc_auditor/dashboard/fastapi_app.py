from __future__ import annotations

import typing

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from pqc_auditor import __version__


def create_app() -> FastAPI:
    app = FastAPI(title="PQC Readiness Dashboard", version=__version__)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return _dashboard_html()

    @app.get("/api/assessment")
    async def assessment(
        score: float = Query(0, ge=0, le=100),
        grade: str = Query("low"),
        weak_count: int = Query(0),
        total_count: int = Query(1),
    ):
        return {
            "score": score,
            "grade": grade,
            "weak_count": weak_count,
            "total_count": total_count,
        }

    @app.post("/api/remediate")
    async def remediate(payload: RemediationRequest):
        return {"algorithm": payload.algorithm, "remediated": payload.count, "status": "planned"}

    return app


class RemediationRequest(BaseModel):
    algorithm: str
    count: int = 1


def _dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>PQC Readiness Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; background: #f7f7f9; }
  .card { background: white; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .grade-critical { color: #c0392b; }
  .grade-high { color: #e67e22; }
  .grade-medium { color: #f1c40f; }
  .grade-low { color: #27ae60; }
</style>
</head>
<body>
<h1>PQC Readiness Dashboard</h1>

<div class="card">
  <div>Overall Score: <span id="score">0</span></div>
  <div>Grade: <span id="grade" class="grade-low">low</span></div>
  <div>Weak Assets: <span id="weak">0</span> / <span id="total">1</span></div>
</div>

<div class="card">
  <canvas id="scoreChart" width="400" height="200"></canvas>
</div>

<div class="card">
  <input id="alg" placeholder="Algorithm" value="ML-DSA" />
  <input id="count" type="number" placeholder="Count" value="1" />
  <button id="remediateBtn">Plan Remediation</button>
  <pre id="remediateResult"></pre>
</div>

<script>
const ctx = document.getElementById('scoreChart').getContext('2d');
new Chart(ctx, { type: 'bar', data: {
  labels: ['Score'],
  datasets: [{ label: 'Risk Score', data: [0], backgroundColor: '#27ae60' }]
}});

async function refresh() {
  const res = await fetch('/api/assessment?score=0&grade=low&weak_count=0&total_count=1');
  const data = await res.json();
  document.getElementById('score').textContent = data.score;
  const gradeEl = document.getElementById('grade');
  gradeEl.textContent = data.grade;
  gradeEl.className = 'grade-' + data.grade;
  document.getElementById('weak').textContent = data.weak_count;
  document.getElementById('total').textContent = data.total_count;
}

document.getElementById('remediateBtn').addEventListener('click', async () => {
  const alg = document.getElementById('alg').value;
  const count = document.getElementById('count').value;
  const res = await fetch('/api/remediate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm: alg, count: Number(count) })
  });
  const data = await res.json();
  document.getElementById('remediateResult').textContent = JSON.stringify(data, null, 2);
});

refresh();
</script>
</body>
</html>"""
