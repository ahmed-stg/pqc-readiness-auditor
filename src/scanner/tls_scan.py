from __future__ import annotations

import socket
import ssl
import typing

from OpenSSL import crypto


class TLSScanner:
    """Perform TLS handshake scans against remote hosts."""

    DEFAULT_PORTS = [443]

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

    def _scan_port(self, host: str, port: int) -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                cipher = ssock.cipher()

                now = datetime.utcnow()
                not_after = datetime.strptime(
                    cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%S%z"
                )
                expired = now.replace(tzinfo=datetime.timezone.utc) > not_after

                return {
                    "host": host,
                    "port": port,
                    "protocol": ssock.version() or "unknown",
                    "cipher": cipher[0] if cipher else "unknown",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "subject": cert.get_subject().CN or "",
                    "issuer": cert.get_issuer().CN or "",
                    "not_after": not_after.isoformat(),
                    "expired": expired,
                    "signature_algorithm": cert.get_signature_algorithm().decode("ascii", errors="replace").lower(),
                    "key_size": cert.get_pubkey().bits,
                    "key_type": _key_type_name(cert.get_pubkey().type),
                    "status": "weak" if self._is_weak(cert) else ("expired" if expired else "ok"),
                }

    @staticmethod
    def _is_weak(cert: crypto.X509) -> bool:
        sig = cert.get_signature_algorithm().decode("ascii", errors="replace").lower()
        if "md5" in sig or "sha1" in sig:
            return True
        pub = cert.get_pubkey()
        if pub.type == crypto.TYPE_RSA and pub.bits < 3072:
            return True
        return False


from datetime import datetime, timezone


def _key_type_name(key_type: int) -> str:
    if key_type == crypto.TYPE_RSA:
        return "rsa"
    if key_type == crypto.TYPE_EC:
        return "ec"
    return "unknown"
