from __future__ import annotations

import typing


class MoscaRiskCalculator:
    """Evaluate risk using Mosca's inequality: X + Y > Z."""

    def __init__(self, quantum_arrival_year: typing.Optional[int] = None) -> None:
        self.quantum_arrival_year = quantum_arrival_year or 2030

    def assess(
        self,
        data_shelf_life_years: float,
        migration_time_years: float,
        asset_tags: typing.Optional[typing.List[str]] = None,
    ) -> dict:
        x = data_shelf_life_years
        y = migration_time_years
        z = self.quantum_arrival_year - 2026

        at_risk = (x + y) > z

        return {
            "data_shelf_life_years": x,
            "migration_time_years": y,
            "quantum_arrival_year": self.quantum_arrival_year,
            "mosca_x": x,
            "mosca_y": y,
            "mosca_z": z,
            "at_risk": at_risk,
            "risk_ratio": (x + y) / max(z, 1),
            "asset_tags": asset_tags or [],
            "recommendation": (
                "Prioritize migration immediately" if at_risk and (x + y) > z * 1.5
                else "Plan migration within current cycle"
            ),
        }
