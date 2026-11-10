from __future__ import annotations

import ast
import os
import typing


WEAK_SOURCE_PATTERNS: typing.List[dict] = [
    {"pattern": "hashlib.md5", "label": "md5 hash usage", "severity": "high"},
    {"pattern": "hashlib.sha1", "label": "sha1 hash usage", "severity": "high"},
    {"pattern": "RSAKey", "label": "legacy RSA key generation", "severity": "medium"},
    {"pattern": "RSA.importKey", "label": "legacy RSA import", "severity": "medium"},
    {"pattern": "cryptography.hazmat.primitives.ciphers", "label": "low-level cipher usage", "severity": "low"},
]


class SourceScanner:
    """Scan source code repos for hardcoded cryptographic calls and secrets."""

    def __init__(self, patterns: typing.Optional[typing.List[dict]] = None) -> None:
        self.patterns = patterns or WEAK_SOURCE_PATTERNS

    def scan(self, path: str) -> dict:
        findings: typing.List[dict] = []
        secrets: typing.List[dict] = []

        for root, _, files in os.walk(path):
            for name in files:
                if name.endswith((".py", ".js", ".ts", ".go", ".java")):
                    fpath = os.path.join(root, name)
                    findings.extend(self._scan_file(fpath))
                    secrets.extend(self._scan_secrets(fpath))

        return {
            "path": path,
            "file_count": len(set(f["file"] for f in findings)) + len(set(s["file"] for s in secrets)),
            "findings": findings,
            "secrets": secrets,
            "status": "scanned",
        }

    def _scan_file(self, path: str) -> typing.List[dict]:
        findings: typing.List[dict] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except Exception:
            return findings

        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._check_import(alias.name, path, findings)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    self._check_import(f"{module}.{alias.name}" if module else alias.name, path, findings)

        for pattern in self.patterns:
            if pattern["pattern"] in source:
                findings.append({
                    "file": path,
                    "type": "crypto_call",
                    "label": pattern["label"],
                    "severity": pattern["severity"],
                    "match": pattern["pattern"],
                })

        return findings

    def _check_import(self, name: str, path: str, findings: typing.List[dict]) -> None:
        for pattern in self.patterns:
            if pattern["pattern"] in name:
                findings.append({
                    "file": path,
                    "type": "crypto_import",
                    "label": pattern["label"],
                    "severity": pattern["severity"],
                    "match": pattern["pattern"],
                })

    def _scan_secrets(self, path: str) -> typing.List[dict]:
        findings: typing.List[dict] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        secret_patterns = [
            (r"(?i)password\s*=\s*['\"]([^'\"]{8,})['\"]", "password literal"),
            (r"(?i)secret\s*=\s*['\"]([^'\"]{8,})['\"]", "secret literal"),
            (r"(?i)api_key\s*=\s*['\"]([^'\"]{8,})['\"]", "api key literal"),
            (r"(?i)ssh-rsa\s+[A-Za-z0-9+/=]{20,}", "embedded ssh key"),
        ]

        import re
        for idx, line in enumerate(lines, start=1):
            for regex, label in secret_patterns:
                m = re.search(regex, line)
                if m:
                    findings.append({
                        "file": path,
                        "type": "secret",
                        "label": label,
                        "severity": "high",
                        "line": idx,
                        "snippet": m.group(0)[:80],
                    })

        return findings
