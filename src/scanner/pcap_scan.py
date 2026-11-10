from __future__ import annotations

import typing

from scapy.all import rdpcap, SSL


class PCAPScanner:
    """Analyze PCAP files for weak TLS/SSL traffic."""

    def __init__(self, min_cipher_bits: int = 128) -> None:
        self.min_cipher_bits = min_cipher_bits

    def analyze(self, path: str) -> dict:
        packets = rdpcap(path)
        findings: typing.List[dict] = []
        tls_sessions: typing.Dict[str, dict] = {}

        for pkt in packets:
            if pkt.haslayer(SSL):
                tls = pkt[SSL]
                rec = tls.record
                if rec.type == 20:  # handshake
                    findings.append({
                        "packet_index": packets.index(pkt),
                        "direction": "server_hello" if tls.s =="server_hello" else "client_hello",
                        "tls_version": tls.version,
                    })

        # Tally summary
        sessions = self._summarize(findings)
        return {
            "file": path,
            "packet_count": len(packets),
            "tls_handshake_count": len(findings),
            "sessions": sessions,
            "status": "analyzed",
        }

    def _summarize(self, findings: typing.List[dict]) -> typing.List[dict]:
        return [{"type": f["direction"], "tls_version": f["tls_version"]} for f in findings]
