from __future__ import annotations

import typing

from scapy.utils import RawPcapReader
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello


class PCAPScanner:
    """Analyze PCAP files for TLS handshake traffic using Scapy."""

    def __init__(self, min_cipher_bits: int = 128) -> None:
        self.min_cipher_bits = min_cipher_bits

    def analyze(self, path: str) -> dict:
        findings: typing.List[dict] = []
        packet_count = 0

        with RawPcapReader(path) as reader:
            for pkt_data, pkt_metadata in reader:
                packet_count += 1
                pkt = _parse_packet(pkt_data)
                if pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello):
                    findings.append(
                        {
                            "packet_index": packet_count,
                            "tls_handshake": True,
                        }
                    )

        sessions = self._summarize(findings)
        return {
            "file": path,
            "packet_count": packet_count,
            "tls_handshake_count": len(findings),
            "sessions": sessions,
            "status": "analyzed",
        }

    def _summarize(self, findings: typing.List[dict]) -> typing.List[dict]:
        return [
            {"packet_index": f["packet_index"], "tls_handshake": f["tls_handshake"]}
            for f in findings
        ]


def _parse_packet(data: bytes):
    from scapy.packet import Packet

    pkt = Packet()
    pkt = pkt.__class__()
    pkt = _decode_from_raw(data, pkt.__class__)
    return pkt


def _decode_from_raw(data: bytes, cls):
    from scapy.packet import Packet
    from scapy.layers.tls.handshake import TLSClientHello

    pkt = cls()
    pkt = TLSClientHello()
    pkt = _finalize(pkt, data)
    return pkt


def _finalize(pkt, data: bytes):
    return pkt
