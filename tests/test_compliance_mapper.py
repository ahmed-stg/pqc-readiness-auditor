from __future__ import annotations

import unittest

from src.risk.compliance_mapper import ComplianceMapper


class TestComplianceMapper(unittest.TestCase):
    def setUp(self):
        self.mapper = ComplianceMapper()

    def test_cnsa2_required_year_is_2027(self):
        result = self.mapper.grade([], standard="CNSA2")
        self.assertEqual(result["required_year"], 2027)
        self.assertEqual(result["standard"], "CNSA2")

    def test_critical_badge_when_many_weak_assets(self):
        findings = [
            {"subject": "a.example.com", "status": "weak", "key_size": 2048},
            {"subject": "b.example.com", "status": "weak", "key_size": 2048},
            {"subject": "c.example.com", "status": "weak", "key_size": 2048},
        ]
        result = self.mapper.grade(findings, standard="CNSA2")
        self.assertIn("Critical", result["badge"])

    def test_compliant_badge_with_no_weak_assets(self):
        findings = [
            {"subject": "a.example.com", "status": "ok", "key_size": 4096},
            {"subject": "b.example.com", "status": "ok", "key_size": 4096},
        ]
        result = self.mapper.grade(findings, standard="CNSA2")
        self.assertIn("Compliant", result["badge"])

    def test_grade_counts_weak_and_strong(self):
        findings = [
            {"subject": "a.example.com", "status": "weak", "key_size": 2048},
            {"subject": "b.example.com", "status": "ok", "key_size": 4096},
        ]
        result = self.mapper.grade(findings, standard="CNSA2")
        self.assertEqual(result["total_assets"], 2)
        self.assertEqual(result["weak_assets"], 1)
        self.assertEqual(result["strong_assets"], 1)
