from __future__ import annotations

import unittest

from OpenSSL import crypto
from src.scanner.tls_scan import TLSScanner


class TestTLSScanWeakDetection(unittest.TestCase):
    def test_is_weak_static_method_exists(self):
        self.assertTrue(hasattr(TLSScanner, "_is_weak"))

    def test_weak_cert_detection(self):
        # Build a minimal RSA 1024 cert and verify the helper flags it as weak
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 1024)
        cert = crypto.X509()
        cert.set_pubkey(key)
        cert.set_serial_number(1)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.sign(key, "sha1")
        self.assertTrue(TLSScanner._is_weak(cert))


if __name__ == "__main__":
    unittest.main()
