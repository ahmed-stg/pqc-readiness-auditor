"""Sample source file with a knowingly weak cryptographic call for demo/testing."""
import hashlib


def compute_fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
