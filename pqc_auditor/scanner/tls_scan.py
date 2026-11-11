from __future__ import annotations

import socket
import ssl
import typing
from datetime import datetime, timezone

from OpenSSL import crypto

from pqc_auditor.schema import Finding, FindingStatus, FindingCategory


class TLSScanner:
    """Perform TLS handshake scans against remote hosts."""

    DEFAULT_PORTS = [443]
    SUPPORTED_KEY_EXCHANGE_GROUPS = [
        "X25519MLKEM768",
        "X25519",
        "secp256r1",
        "secp384r1",
    ]

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def scan(self, host: str, ports: typing.Optional[typing.List[int]] = None) -> dict:
        ports = ports or self.DEFAULT_PORTS
        results: typing.List[dict] = []

        for port in ports:
            try:
                result = self._scan_port(host, port)
                results.append(result)
            except Exception as e:
                results.append({"host": host, "port": port, "error": str(e), "status": "error"})

        return {"host": host, "ports": results}

    def _scan_port(self, host: str, port: int) -> Finding:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                    cipher = ssock.cipher()

                    now = datetime.now(timezone.utc)
                    not_after = datetime.strptime(
                        cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%S%z"
                    )
                    expired = now > not_after

                    return self._build_finding(
                        host=host,
                        port=port,
                        protocol=ssock.version() or "unknown",
                        cipher_name=cipher[0] if cipher else "unknown",
                        cipher_bits=cipher[2] if cipher else 0,
                        cert=cert,
                        not_after=not_after,
                        expired=expired,
                        negotiated_groups=[],
                    )
        except Exception as e:
            return Finding(
                host=host,
                port=port,
                status=FindingStatus.ERROR,
                error=str(e),
            )

    def _build_finding(
        self,
        host: str,
        port: int,
        protocol: str,
        cipher_name: str,
        cipher_bits: int,
        cert: crypto.X509,
        not_after: datetime,
        expired: bool,
        negotiated_groups: typing.List[str],
    ) -> Finding:
        sig_alg = cert.get_signature_algorithm().decode("ascii", errors="replace").lower()
        pubkey = cert.get_pubkey()
        key_type = pubkey.type() if callable(pubkey.type) else pubkey.type
        key_size = pubkey.bits() if callable(pubkey.bits) else pubkey.bits

        findings: typing.List[str] = []
        category = FindingCategory.OK

        if "md5" in sig_alg or "sha1" in sig_alg:
            findings.append("weak signature algorithm")
            category = FindingCategory.CLASSICALLY_WEAK
        if key_type in (crypto.TYPE_RSA, crypto.TYPE_EC) and not findings:
            findings.append("quantum-vulnerable key algorithm")
            category = FindingCategory.QUANTUM_VULNERABLE
        if expired:
            findings.append("certificate expired")
            category = FindingCategory.CLASSICALLY_WEAK

        if negotiated_groups:
            if any(g.startswith("MLKEM") or g.startswith("mlkem") for g in negotiated_groups):
                category = FindingCategory.HYBRID_PQC_READY

        return Finding(
            host=host,
            port=port,
            protocol=protocol,
            cipher_name=cipher_name,
            cipher_bits=cipher_bits,
            subject=cert.get_subject().CN or "",
            issuer=cert.get_issuer().CN or "",
            not_after=not_after.isoformat(),
            expired=expired,
            signature_algorithm=sig_alg,
            key_type=TLSScanner._key_type_name(key_type),
            key_size=key_size,
            negotiated_key_exchange_groups=negotiated_groups,
            findings=findings,
            category=category,
            status=(FindingStatus.EXPIRED if expired else FindingStatus.WEAK) if findings else FindingStatus.OK,
        )

    @staticmethod
    def _key_type_name(key_type: int) -> str:
        if key_type == crypto.TYPE_RSA:
            return "rsa"
        if key_type == crypto.TYPE_EC:
            return "ec"
        return "unknown"

