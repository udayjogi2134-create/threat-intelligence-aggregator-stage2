import unittest
from ioc_parser import parse_upload

class ParserTests(unittest.TestCase):
    def test_csv_structured_ioc(self):
        data = b"type,value\nIP,192.0.2.1\n"
        found, rejected = parse_upload("feed.csv", data)
        self.assertIn(("IP", "192.0.2.1", "feed.csv"), found)
        self.assertEqual(rejected, [])

    def test_invalid_csv_ioc_rejected(self):
        found, rejected = parse_upload("feed.csv", b"type,value\nIP,999.1.1.1\n")
        self.assertEqual(len(found), 0)
        self.assertEqual(len(rejected), 1)

    def test_malformed_json_raises(self):
        with self.assertRaises(ValueError):
            parse_upload("feed.json", b"{bad json")

if __name__ == "__main__":
    unittest.main()
