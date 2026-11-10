from __future__ import annotations

import typing


STANDARDS = {
    "NIST-8547": {
        "timelines": {
            "legacy_alg_deprecated": 2023,
            "cnsa2_aligned": 2025,
            "full_pqc_transition": 2030,
        },
        "deprecated_algorithms": ["md5", "sha1", "rsa-1024", "rsa-2048"],
    },
    "CNSA2": {
        "timelines": {
            "transition_start": 2025,
            "cnsa2_required": 2027,
            "full_pqc_required": 2033,
        },
        "approved_algorithms": ["ml-dsa", "x25519mlkem768", "sha-384"],
    },
}


class ComplianceMapper:
    """Grade findings against NIST IR 8547 and CNSA 2.0 requirements."""

    def __init__(self, standards: typing.Optional[typing.Dict[str, dict]] = None) -> None:
        self.standards = standards or STANDARDS

    def grade(self, findings: typing.List[dict], standard: str = "CNSA2") -> dict:
        std = self.standards.get(standard, self.standards["CNSA2"])
        now_year = 2026

        weak_alg_count = 0
        strong_alg_count = 0
        total = 0

        for f in findings:
            if "key_size" in f:
                total += 1
                if f.get("status") == "weak":
                    weak_alg_count += 1
                else:
                    strong_alg_count += 1

        required_year = std["timelines"].get("cnsa2_required", 2027)
        progress = self._compute_progress(now_year, required_year, weak_alg_count, total)

        badge = self._badge(progress, required_year, now_year)

        return {
            "standard": standard,
            "assessed_year": now_year,
            "required_year": required_year,
            "total_assets": total,
            "weak_assets": weak_alg_count,
            "strong_assets": strong_alg_count,
            "compliance_percentage": progress,
            "badge": badge,
            "timelines": std["timelines"],
        }

    def _compute_progress(self, now_year: int, required_year: int, weak: int, total: int) -> float:
        if total == 0:
            return 100.0
        remaining_years = max(required_year - now_year, 1)
        progress_ratio = 1 - (weak / total)
        time_factor = max(0.0, 1 - (required_year - now_year) / 10)
        return round((progress_ratio * 0.7 + time_factor * 0.3) * 100, 1)

    def _badge(self, progress: float, required_year: int, now_year: int) -> str:
        if progress >= 90 and required_year > now_year:
            return f"{required_year} CNSA Compliant"
        if progress >= 70:
            return "On Track"
        if progress >= 40:
            return "Action Required"
        return "Critical Action Required"
