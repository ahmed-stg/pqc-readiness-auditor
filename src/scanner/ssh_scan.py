from __future__ import annotations

import typing

import paramiko


class SSHScanner:
    """Inspect SSH server host keys and supported algorithms."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def inspect(self, host: str, port: int = 22, username: typing.Optional[str] = None, password: typing.Optional[str] = None) -> dict:
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
            return {"host": host, "port": port, "error": str(e), "status": "connection_failed"}

        host_keys = client.get_host_keys()
        keys_info: typing.List[dict] = []

        for key_type, key in host_keys.get(host, {}).items():
            keys_info.append({
                "key_type": key_type,
                "key_size": key.get_bits(),
                "fingerprint": key.get_fingerprint().hex(),
                "weak": _is_weak_ssh_key(key_type, key.get_bits()),
            })

        transport = client.get_transport()
        transport.close()

        return {
            "host": host,
            "port": port,
            "host_keys": keys_info,
            "status": "ok",
        }


def _is_weak_ssh_key(key_type: str, key_size: int) -> bool:
    if key_type in ("ssh-rsa", "rsa-sha1"):
        return key_size < 3072
    if key_type in ("ssh-dss", "dsa"):
        return True
    return False
