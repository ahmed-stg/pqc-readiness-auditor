from __future__ import annotations

import ast
import os
import re
import typing

from pqc_auditor.schema import Finding, FindingStatus, FindingCategory

CLASSICAL_SOURCE_PATTERNS = [
    {"pattern": "hashlib.md5", "label": "md5 hash usage", "category": FindingCategory.CLASSICALLY_WEAK},
    {"pattern": "hashlib.sha1", "label": "sha1 hash usage", "category": FindingCategory.CLASSICALLY_WEAK},
]

QUANTUM_SOURCE_PATTERNS = [
    {"pattern": "rsa.generate_private_key", "label": "rsa key generation", "category": FindingCategory.QUANTUM_VULNERABLE},
    {"pattern": "ec.generate_private_key", "label": "ec key generation", "category": FindingCategory.QUANTUM_VULNERABLE},
    {"pattern": "Cipher(", "label": "low-level cipher usage", "category": FindingCategory.CLASSICALLY_WEAK},
    {"pattern": "RSA.key", "label": "legacy RSA key handling", "category": FindingCategory.QUANTUM_VULNERABLE},
]

SECRET_PATTERNS = [
    (r"(?i)password\s*=\s*['\"]([^'\"]{8,})['\"]", "password literal"),
    (r"(?i)secret\s*=\s*['\"]([^'\"]{8,})['\"]", "secret literal"),
    (r"(?i)api_key\s*=\s*['\"]([^'\"]{8,})['\"]", "api key literal"),
    (r"(?i)ssh-rsa\s+[A-Za-z0-9+/=]{20,}", "embedded ssh key"),
]


class SourceScanner:
    """Scan source code repos for hardcoded cryptographic calls and secrets."""

    def __init__(self) -> None:
        self.patterns = CLASSICAL_SOURCE_PATTERNS + QUANTUM_SOURCE_PATTERNS

    def scan(self, path: str) -> Finding:
        findings: typing.List[dict] = []
        secrets: typing.List[dict] = []

        for root, _, files in os.walk(path):
            for name in files:
                if name.endswith((".py", ".js", ".ts", ".go", ".java")):
                    fpath = os.path.join(root, name)
                    findings.extend(self._scan_file(fpath))
                    secrets.extend(self._scan_secrets(fpath))

        return Finding(
            path=path,
            file_count=len(set(f.get("file") for f in findings)) + len(set(s.get("file") for s in secrets)),
            findings=findings,
            secrets=secrets,
            status=FindingStatus.OK,
        )

    def _scan_file(self, path: str) -> typing.List[dict]:
        findings: typing.List[dict] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except Exception:
            return findings

        try:
            tree = ast.parse(source)
        except Exception:
            tree = None

        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self._check_import(alias.name, path, findings)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        full = f"{module}.{alias.name}" if module else alias.name
                        self._check_import(full, path, findings)

        for pattern in self.patterns:
            if pattern["pattern"] in source:
                findings.append(
                    {
                        "file": path,
                        "type": "crypto_call",
                        "label": pattern["label"],
                        "category": pattern["category"],
                        "match": pattern["pattern"],
                    }
                )

        return findings

    def _check_import(self, name: str, path: str, findings: typing.List[dict]) -> None:
        for pattern in self.patterns:
            if pattern["pattern"] in name:
                findings.append(
                    {
                        "file": path,
                        "type": "crypto_import",
                        "label": pattern["label"],
                        "category": pattern["category"],
                        "match": pattern["pattern"],
                    }
                )

    def _scan_secrets(self, path: str) -> typing.List[dict]:
        findings: typing.List[dict] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for idx, line in enumerate(lines, start=1):
            for regex, label in SECRET_PATTERNS:
                m = re.search(regex, line)
                if m:
                    findings.append(
                        {
                            "file": path,
                            "type": "secret",
                            "label": label,
                            "severity": "high",
                            "line": idx,
                            "snippet": m.group(0)[:80],
                        }
                    )

        return findings
