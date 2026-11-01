import unittest
from normalizer import normalize_ioc

class NormalizerTests(unittest.TestCase):
    def test_ipv4_canonical(self):
        self.assertEqual(normalize_ioc("IP", "192.0.2.1"), "192.0.2.1")

    def test_domain_lowercase(self):
        self.assertEqual(normalize_ioc("DOMAIN", "Example.COM."), "example.com")

    def test_invalid_ip_rejected(self):
        with self.assertRaises(ValueError):
            normalize_ioc("IP", "999.999.1.1")

    def test_hash_lowercase(self):
        self.assertEqual(normalize_ioc("HASH", "A" * 32), "a" * 32)

    def test_url_credentials_rejected(self):
        with self.assertRaises(ValueError):
            normalize_ioc("URL", "https://user:pass@example.com/path")

if __name__ == "__main__":
    unittest.main()
