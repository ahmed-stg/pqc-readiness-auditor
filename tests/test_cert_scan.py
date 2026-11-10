from __future__ import annotations

import os
import tempfile
import unittest

from OpenSSL import crypto

from src.scanner.cert_scan import CertScanner


class TestCertScan(unittest.TestCase):
    def test_weak_rsa_2048_cert_is_flagged(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.set_pubkey(key)
        cert.set_serial_number(1)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.sign(key, "sha256")

        scanner = CertScanner()
        result = scanner.scan_cert(cert, path="sample.pem")
        self.assertEqual(result["key_type"], "rsa")
        self.assertEqual(result["key_size"], 2048)
        self.assertIn("rsa key too small", result["weakness"])
        self.assertEqual(result["status"], "weak")

    def test_file_not_found_raises(self):
        scanner = CertScanner()
        with self.assertRaises(FileNotFoundError):
            scanner.scan_file("/path/does/not/exist.pem")

    def test_scan_directory_yields_results_and_includes_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(os.path.dirname(__file__), "..", "samples")
            dest = os.path.join(tmp, "certs")
            os.makedirs(dest)
            weak = os.path.join(src, "weak_cert.pem")
            os.symlink(os.path.abspath(weak), os.path.join(dest, "link.pem"))

            scanner = CertScanner()
            results = scanner.scan_directory(dest)
            self.assertTrue(results)
            self.assertTrue(any("weak_cert.pem" in r.get("file", "") or "link.pem" in r.get("file", "") for r in results))
