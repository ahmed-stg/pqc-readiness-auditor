from __future__ import annotations

import typing

from scapy.utils import RawPcapReader

from pqc_auditor.schema import Finding, FindingStatus


class PCAPScanner:
    """Analyze PCAP files for TLS handshake traffic using Scapy."""

    def __init__(self) -> None:
        pass

    def analyze(self, path: str) -> Finding:
        from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello

        packet_count = 0
        tls_handshake_count = 0

        with RawPcapReader(path) as reader:
            for pkt_data, pkt_metadata in reader:
                packet_count += 1
                pkt = _parse_packet(pkt_data)
                if pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello):
                    tls_handshake_count += 1

        if packet_count == 0:
            return Finding(
                file=path,
                status=FindingStatus.ERROR,
                error="No packets found in capture",
            )

        return Finding(
            file=path,
            packet_count=packet_count,
            tls_handshake_count=tls_handshake_count,
            status=FindingStatus.OK,
        )


def _parse_packet(data: bytes):
    from scapy.layers.l2 import Ether
    return Ether(data)

