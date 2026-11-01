import unittest
from risk_engine import score_indicator, severity

class RiskEngineTests(unittest.TestCase):
    def test_repeated_source_score_increases(self):
        self.assertGreater(score_indicator("DOMAIN", 2), score_indicator("DOMAIN", 1))

    def test_score_caps_at_100(self):
        self.assertEqual(score_indicator("URL", 99), 100)

    def test_severity_bands(self):
        self.assertEqual(severity(20), "Low")
        self.assertEqual(severity(40), "Medium")
        self.assertEqual(severity(60), "High")
        self.assertEqual(severity(80), "Critical")

if __name__ == "__main__":
    unittest.main()
