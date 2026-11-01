"""Safe local feed imports and opt-in HTTPS fetching."""
from urllib.parse import urlsplit
import requests
from config import MAX_UPLOAD_BYTES, REQUEST_TIMEOUT_SECONDS, USER_AGENT, ALLOWED_FEED_SCHEMES
from ioc_parser import parse_upload
import database

def process_local_upload(filename, raw_bytes):
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError(f"file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit")
    try:
        indicators, rejected = parse_upload(filename, raw_bytes, source=filename)
        database.upsert_indicators(indicators)
        database.record_feed_run(filename, "success", len(indicators), rejected)
        return len(indicators), len(rejected)
    except Exception as exc:
        database.record_feed_run(filename, "failed", 0, [], error=str(exc))
        raise

def fetch_https_feed(url, source_name=None):
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_FEED_SCHEMES or not parts.hostname:
        raise ValueError("only explicit HTTPS feed URLs are accepted")
    # Do not follow redirects to another host; avoid silently trusting redirect destinations.
    response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS,
                            headers={"User-Agent": USER_AGENT}, allow_redirects=False)
    if response.is_redirect:
        raise ValueError("feed redirected; inspect the destination and configure it explicitly")
    response.raise_for_status()
    if len(response.content) > MAX_UPLOAD_BYTES:
        raise ValueError("downloaded feed exceeds size limit")
    name = source_name or parts.hostname
    filename = "feed." + (parts.path.rsplit(".", 1)[-1].lower() if "." in parts.path else "txt")
    if filename.rsplit(".", 1)[-1] not in {"csv", "txt", "json"}:
        raise ValueError("URL path must end in .csv, .txt or .json")
    indicators, rejected = parse_upload(filename, response.content, source=name)
    database.upsert_indicators(indicators)
    database.record_feed_run(name, "success", len(indicators), rejected)
    return len(indicators), len(rejected)
