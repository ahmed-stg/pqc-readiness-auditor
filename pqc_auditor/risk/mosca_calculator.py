from __future__ import annotations

import typing

from pqc_auditor.schema import MoscaScenario, MoscaAssessment

MOSCA_SCENARIOS: typing.Dict[MoscaScenario, int] = {
    MoscaScenario.OPTIMISTIC: 2040,
    MoscaScenario.MEDIAN: 2035,
    MoscaScenario.CONSERVATIVE: 2030,
}


class MoscaRiskCalculator:
    """Evaluate risk using Mosca's inequality: X + Y > Z."""

    def __init__(self, scenario: MoscaScenario = MoscaScenario.MEDIAN) -> None:
        self.scenario = scenario

    def assess(
        self,
        data_shelf_life_years: float,
        migration_time_years: float,
        asset_tags: typing.Optional[typing.List[str]] = None,
    ) -> MoscaAssessment:
        x = data_shelf_life_years
        y = migration_time_years
        z = MOSCA_SCENARIOS[self.scenario] - 2026

        at_risk = (x + y) > z
        margin_years = z - (x + y)

        recommendation = (
            "Prioritize migration immediately"
            if margin_years < -5
            else (
                "Plan migration within current cycle"
                if margin_years < 0
                else "No urgent action required under this scenario"
            )
        )

        return MoscaAssessment(
            data_shelf_life_years=x,
            migration_time_years=y,
            quantum_arrival_year=MOSCA_SCENARIOS[self.scenario],
            quantum_arrival_scenario=self.scenario,
            mosca_x=x,
            mosca_y=y,
            mosca_z=z,
            at_risk=at_risk,
            margin_years=round(margin_years, 2),
            risk_ratio=round((x + y) / max(z, 1), 2),
            recommendation=recommendation,
        )
