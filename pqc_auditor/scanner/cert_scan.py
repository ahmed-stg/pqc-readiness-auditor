from __future__ import annotations

import datetime
import os
import typing

from OpenSSL import crypto

from pqc_auditor.schema import Finding, FindingStatus, FindingCategory


class CertScanner:
    """Scan certificate files for cryptographic weaknesses and expiry."""

    def __init__(self) -> None:
        pass

    def scan_file(self, path: str) -> Finding:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)

        with open(path, "rb") as f:
            data = f.read()

        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        except crypto.Error:
            try:
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, data)
            except crypto.Error:
                return Finding(
                    file=path,
                    status=FindingStatus.ERROR,
                    error="Not a recognized certificate format",
                )

        return self.scan_cert(cert, path)

    def scan_cert(self, cert: crypto.X509, path: str = "") -> Finding:
        not_after = datetime.datetime.strptime(
            cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%S%z"
        )
        not_before = datetime.datetime.strptime(
            cert.get_notBefore().decode("ascii"), "%Y%m%d%H%M%S%z"
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        expired = now > not_after
        not_yet_valid = now < not_before

        sig_alg = cert.get_signature_algorithm().decode("ascii", errors="replace").lower()
        pubkey = cert.get_pubkey()
        key_type = pubkey.type() if callable(pubkey.type) else pubkey.type
        key_size = pubkey.bits() if callable(pubkey.bits) else pubkey.bits

        findings: typing.List[str] = []
        category = FindingCategory.OK

        if "md5" in sig_alg or "sha1" in sig_alg:
            findings.append("weak signature algorithm")
            category = FindingCategory.CLASSICALLY_WEAK
        if key_type == crypto.TYPE_RSA and key_size < 2048:
            findings.append("rsa key below 2048 bits")
            category = FindingCategory.CLASSICALLY_WEAK
        if key_type in (crypto.TYPE_RSA, crypto.TYPE_EC) and not findings:
            findings.append("quantum-vulnerable key algorithm")
            category = FindingCategory.QUANTUM_VULNERABLE
        if expired:
            findings.append("certificate expired")
            category = FindingCategory.CLASSICALLY_WEAK

        return Finding(
            file=path,
            subject=cert.get_subject().CN or "",
            issuer=cert.get_issuer().CN or "",
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
            expired=expired,
            not_yet_valid=not_yet_valid,
            signature_algorithm=sig_alg,
            key_type=self._key_type_name(key_type),
            key_size=key_size,
            findings=findings,
            category=category,
            status=FindingStatus.WEAK if findings else (FindingStatus.EXPIRED if expired else FindingStatus.OK),
        )

    def scan_directory(self, directory: str) -> typing.List[Finding]:
        results: typing.List[Finding] = []
        for root, _, files in os.walk(directory):
            for name in files:
                if name.lower().endswith((".pem", ".crt", ".cer", ".der")):
                    path = os.path.join(root, name)
                    try:
                        results.append(self.scan_file(path))
                    except Exception as e:
                        results.append(Finding(file=path, status=FindingStatus.ERROR, error=str(e)))
        return results

    @staticmethod
    def _key_type_name(key_type: int) -> str:
        if key_type == crypto.TYPE_RSA:
            return "rsa"
        if key_type == crypto.TYPE_EC:
            return "ec"
        return f"unknown-{key_type}"
