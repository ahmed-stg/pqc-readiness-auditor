from __future__ import annotations

import unittest

from pqc_auditor.risk.mosca_calculator import MoscaRiskCalculator
from pqc_auditor.schema import MoscaScenario


class TestMoscaCalculator(unittest.TestCase):
    def setUp(self):
        self.calc = MoscaRiskCalculator(scenario=MoscaScenario.CONSERVATIVE)

    def test_at_risk_when_shelf_plus_migration_exceeds_quantum_arrival(self):
        result = self.calc.assess(data_shelf_life_years=10, migration_time_years=5)
        self.assertTrue(result["at_risk"])

    def test_not_at_risk_when_under_threshold(self):
        result = self.calc.assess(data_shelf_life_years=2, migration_time_years=1)
        self.assertFalse(result["at_risk"])

    def test_recommendation_for_high_risk(self):
        result = self.calc.assess(data_shelf_life_years=20, migration_time_years=8)
        self.assertIn("migration", result["recommendation"].lower())


if __name__ == "__main__":
    unittest.main()
