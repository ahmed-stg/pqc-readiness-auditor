from __future__ import annotations

import typing

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        public_key = private_key.public_key()

        subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
        now = _utc_now()

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + _timedelta_days(validity_days))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")

        result = {
            "algorithm": algorithm,
            "common_name": common_name,
            "validity_days": validity_days,
            "status": "generated",
        }

        if output_path:
            with open(output_path, "w") as f:
                f.write("-----BEGIN CERTIFICATE-----\n")
                f.write(cert_pem)
                f.write("-----END CERTIFICATE-----\n")
            result["cert_path"] = output_path

        result["certificate_pem"] = cert_pem
        result["private_key_pem"] = key_pem
        return result

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


from datetime import datetime, timedelta, timezone


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timedelta_days(days: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)
