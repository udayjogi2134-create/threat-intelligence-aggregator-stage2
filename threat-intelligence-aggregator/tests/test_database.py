import unittest
import database

class DatabaseTests(unittest.TestCase):
    def test_database_functions_smoke(self):
        # This test verifies the public API against the configured database path.
        # For isolated CI, point config.DB_PATH and config.DATA_DIR at a temporary directory.
        database.init_db()
        self.assertIsInstance(database.list_indicators(), list)
        self.assertIsInstance(database.list_feed_runs(), list)

if __name__ == "__main__":
    unittest.main()
