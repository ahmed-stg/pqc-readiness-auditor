from __future__ import annotations

import typing

import paramiko

from pqc_auditor.schema import Finding, FindingStatus, FindingCategory


class SSHScanner:
    """Inspect SSH server host keys and key exchange offers."""

    PQC_KEX_OFFER_PATTERNS = ("mlkem768x25519", "sntrup761x25519", "mlkem768x25519-sha256")

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def inspect(
        self,
        host: str,
        port: int = 22,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
    ) -> Finding:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=host,
                port=port,
                timeout=self.timeout,
                username=username,
                password=password,
                look_for_keys=False,
                allow_agent=False,
            )
        except Exception as e:
            return Finding(
                host=host,
                port=port,
                status=FindingStatus.ERROR,
                error=str(e),
            )

        host_keys = client.get_host_keys()
        keys_info: typing.List[dict] = []
        kex_offers: typing.List[str] = []

        for key_type, key in host_keys.get(host, {}).items():
            keys_info.append(
                {
                    "key_type": key_type,
                    "key_size": key.get_bits(),
                    "fingerprint": key.get_fingerprint().hex().lower(),
                    "quantum_vulnerable": _is_quantum_vulnerable_ssh_key(key_type),
                    "classically_weak": _is_classically_weak_ssh_key(key_type, key.get_bits()),
                }
            )

        transport = client.get_transport()
        if transport is not None:
            kex_offers = self._extract_kex_offers(transport)
            transport.close()

        findings: typing.List[str] = []
        category = FindingCategory.OK

        if any(k.get("classically_weak") for k in keys_info):
            findings.append("classically weak SSH host key")
            category = FindingCategory.CLASSICALLY_WEAK
        elif any(k.get("quantum_vulnerable") for k in keys_info):
            findings.append("quantum-vulnerable SSH host key")
            category = FindingCategory.QUANTUM_VULNERABLE
        if any(p in kex_offers for p in self.PQC_KEX_OFFER_PATTERNS):
            category = FindingCategory.HYBRID_PQC_READY
            findings.append("PQC-capable key exchange offered")

        return Finding(
            host=host,
            port=port,
            host_keys=keys_info,
            kex_offers=kex_offers,
            findings=findings,
            category=category,
            status=FindingStatus.WEAK if findings else FindingStatus.OK,
        )

    def _extract_kex_offers(self, transport: typing.Any) -> typing.List[str]:
        try:
            server_kex = getattr(transport, "server_kex", None)
            if isinstance(server_kex, dict):
                return list(server_kex.keys())
        except Exception:
            pass
        return []


def _is_classically_weak_ssh_key(key_type: str, key_size: int) -> bool:
    if key_type in ("ssh-dss", "dsa"):
        return True
    if key_type in ("ssh-rsa", "rsa-sha1") and key_size < 2048:
        return True
    return False


def _is_quantum_vulnerable_ssh_key(key_type: str) -> bool:
    return key_type in ("ssh-rsa", "rsa-sha1", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521")
