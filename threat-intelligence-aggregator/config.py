from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SAMPLES_DIR = DATA_DIR / "samples"
EXPORTS_DIR = BASE_DIR / "exports"
DB_PATH = DATA_DIR / "threat_intel.sqlite3"

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 12
USER_AGENT = "ThreatIntelligenceAggregator/1.0 (defensive research)"
ALLOWED_FEED_SCHEMES = {"https"}
