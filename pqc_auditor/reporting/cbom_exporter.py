from __future__ import annotations

import typing


class CBOMExporter:
    """Export cryptographic findings to CycloneDX CBOM JSON format."""

    def export(self, findings: typing.List[dict], output_path: typing.Optional[str] = None, format: str = "cyclonedx") -> dict:
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{_uuid()}",
            "version": 1,
            "metadata": {
                "timestamp": _now_iso(),
                "tools": [{"name": "PQC Readiness Auditor", "version": "0.2.0"}],
                "component": {
                    "type": "application",
                    "name": "Scanned Environment",
                    "version": "1.0.0",
                },
            },
            "components": [_component_from_finding(f) for f in findings],
        }

        if output_path:
            import json
            with open(output_path, "w") as f:
                json.dump(bom, f, indent=2)
        return bom


def _component_from_finding(f: dict) -> dict:
    alg = f.get("signature_algorithm", "") or f.get("algorithm", "")
    return {
        "type": "cryptographic-asset",
        "name": f.get("subject") or f.get("file") or f.get("host", "unknown"),
        "version": f.get("not_after", ""),
        "description": f.get("findings", f.get("weakness", [])),
        "purl": f"pkg:generic/{f.get('file', 'asset')}",
        "cryptoProperties": {
            "algorithm": alg,
            "keySize": f.get("key_size", f.get("key_bits", 0)),
            "signatureAlgorithm": f.get("signature_algorithm", ""),
            "validFrom": f.get("not_before", ""),
            "validTo": f.get("not_after", ""),
        },
        "hashes": [{"alg": "SHA-256", "content": f.get("fingerprint", "")[:64]}] if f.get("fingerprint") else [],
    }


def _uuid() -> str:
    import uuid
    return str(uuid.uuid4())


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
