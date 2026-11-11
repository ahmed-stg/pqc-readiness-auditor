from __future__ import annotations

import typing


class CryptoRemediator:
    """Generate hybrid or PQC-ready certificates for remediation."""

    SUPPORTED_PQC_ALGORITHMS = ["ML-DSA", "X25519MLKEM768"]

    def __init__(self) -> None:
        pass

    def generate_hybrid_cert(
        self,
        common_name: str = "pqc-remediated.example.com",
        algorithm: str = "ML-DSA",
        validity_days: int = 365,
        output_path: typing.Optional[str] = None,
    ) -> dict:
        if algorithm not in self.SUPPORTED_PQC_ALGORITHMS:
            return {"error": f"Unsupported PQC algorithm: {algorithm}", "status": "unsupported"}

        return {
            "error": (
                f"{algorithm} certificate generation is unavailable: cryptography's installed backend "
                "does not provide a PQC key implementation. No classical substitute was generated."
            ),
            "status": "unsupported",
        }

    def remediate_findings(self, findings: typing.List[dict], algorithm: str = "ML-DSA") -> dict:
        remediated = 0
        for f in findings:
            if f.get("status") in ("weak", "expired"):
                if self._can_remediate(f):
                    remediated += 1
        return {
            "algorithm": algorithm,
            "remediated_count": remediated,
            "status": "planned",
        }

    def _can_remediate(self, f: dict) -> bool:
        return f.get("key_type") in ("rsa", "ec")
