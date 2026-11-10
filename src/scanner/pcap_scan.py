from __future__ import annotations

import typing

from scapy.all import rdpcap
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello


class PCAPScanner:
    """Analyze PCAP files for encrypted traffic (TLS/DTLS) using Scapy."""

    def __init__(self, min_cipher_bits: int = 128) -> None:
        self.min_cipher_bits = min_cipher_bits

    def analyze(self, path: str) -> dict:
        packets = rdpcap(path)
        findings: typing.List[dict] = []

        for i, pkt in enumerate(packets):
            if pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello):
                findings.append({
                    "packet_index": i,
                    "tls_handshake": True,
                })

        summary = self._summarize(findings)
        return {
            "file": path,
            "packet_count": len(packets),
            "tls_handshake_count": len(findings),
            "sessions": summary,
            "status": "analyzed",
        }

    def _summarize(self, findings: typing.List[dict]) -> typing.List[dict]:
        return [{"packet_index": f["packet_index"], "tls_handshake": f["tls_handshake"]} for f in findings]
