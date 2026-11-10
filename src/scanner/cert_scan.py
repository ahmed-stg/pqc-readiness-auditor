from __future__ import annotations

import datetime
import hashlib
import os
import typing

from OpenSSL import crypto


class CertScanner:
    """Scan certificate files for cryptographic weaknesses and expiry."""

    WEAK_ALGORITHMS = {"md5", "sha1", "rsa-1024", "rsa-2048"}

    def __init__(self, weak_algorithms: typing.Optional[typing.Set[str]] = None) -> None:
        self.weak_algorithms = weak_algorithms or self.WEAK_ALGORITHMS

    def scan_file(self, path: str) -> dict:
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
                return {
                    "file": path,
                    "error": "Not a recognized certificate format",
                    "status": "unreadable",
                }

        return self.scan_cert(cert, path)

    def scan_cert(self, cert: crypto.X509, path: str = "") -> dict:
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
        key_type = pubkey.type
        key_size = pubkey.bits

        weakness = []
        if "md5" in sig_alg or "sha1" in sig_alg:
            weakness.append("weak signature algorithm")
        if key_type == crypto.TYPE_RSA and key_size < 3072:
            weakness.append("rsa key too small")
        if key_size < 2048:
            weakness.append("key size below 2048 bits")

        return {
            "file": path,
            "subject": cert.get_subject().CN or "",
            "issuer": cert.get_issuer().CN or "",
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "expired": expired,
            "not_yet_valid": not_yet_valid,
            "signature_algorithm": sig_alg,
            "key_type": self._key_type_name(key_type),
            "key_size": key_size,
            "weakness": weakness,
            "status": "weak" if weakness else ("expired" if expired else "ok"),
        }

    def scan_directory(self, directory: str) -> typing.List[dict]:
        results: typing.List[dict] = []
        for root, _, files in os.walk(directory):
            for name in files:
                if name.lower().endswith((".pem", ".crt", ".cer", ".der")):
                    path = os.path.join(root, name)
                    try:
                        results.append(self.scan_file(path))
                    except Exception as e:
                        results.append({"file": path, "error": str(e), "status": "error"})
        return results

    @staticmethod
    def _key_type_name(key_type: int) -> str:
        if key_type == crypto.TYPE_RSA:
            return "rsa"
        if key_type == crypto.TYPE_EC:
            return "ec"
        return f"unknown-{key_type}"
