from __future__ import annotations

import unittest

from OpenSSL import crypto
from pqc_auditor.scanner.tls_scan import TLSScanner


class TestTLSScanWeakDetection(unittest.TestCase):
    def test_supported_key_exchange_groups_include_mlkem_hybrid(self):
        self.assertIn("X25519MLKEM768", TLSScanner.SUPPORTED_KEY_EXCHANGE_GROUPS)

    def test_tls_scanner_produces_negotiated_groups_field(self):
        self.assertTrue(hasattr(TLSScanner, "_build_finding"))
        import inspect
        sig = inspect.signature(TLSScanner._build_finding)
        self.assertIn("negotiated_groups", sig.parameters)


if __name__ == "__main__":
    unittest.main()
