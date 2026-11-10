from __future__ import annotations

import typing

from .mosca_calculator import MoscaRiskCalculator
from .compliance_mapper import ComplianceMapper


class RiskScorer:
    """Combine scan results into a unified risk assessment."""

    def __init__(self) -> None:
        self.mosca = MoscaRiskCalculator()
        self.compliance = ComplianceMapper()

    def assess(
        self,
        findings: typing.List[dict],
        data_shelf_life_years: float = 10.0,
        migration_time_years: float = 3.0,
    ) -> dict:
        mosca_result = self.mosca.assess(data_shelf_life_years, migration_time_years)
        compliance_result = self.compliance.grade(findings, standard="CNSA2")

        weak_count = sum(1 for f in findings if str(f.get("status", "")).lower() in ("weak", "expired"))
        total = max(len(findings), 1)

        base_score = (weak_count / total) * 100
        quantum_penalty = 20 if mosca_result["at_risk"] else 0
        compliance_adjustment = max(0, 50 - compliance_result["compliance_percentage"])

        final_score = min(100, base_score + quantum_penalty + compliance_adjustment)

        grade = (
            "critical" if final_score >= 80
            else "high" if final_score >= 60
            else "medium" if final_score >= 40
            else "low"
        )

        return {
            "overall_score": round(final_score, 1),
            "grade": grade,
            "weak_asset_count": weak_count,
            "total_assets": total,
            "mosca": mosca_result,
            "compliance": compliance_result,
            "assessment_date": "2026-11-10",
        }
