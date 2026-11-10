from __future__ import annotations

import unittest

from src.scanner.tls_scan import TLSScanner


class TestTLSScanWeakDetection(unittest.TestCase):
    def test_is_weak_with_small_rsa(self):
        scanner = TLSScanner()
        self.assertTrue(scanner._is_weak)


if __name__ == "__main__":
    unittest.main()
