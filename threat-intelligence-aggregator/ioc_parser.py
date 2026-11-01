"""IOC parsing for structured CSV/JSON fields and plain text feeds."""
import csv
import io
import json
import re
from normalizer import normalize_ioc

PATTERNS = {
    "URL": re.compile(r"https?://[^\s\"'<>]+", re.I),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "HASH": re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"),
    "IP": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])"),
    "DOMAIN": re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"),
}
TYPE_ALIASES = {
    "IP": "IP", "IP_ADDRESS": "IP", "IPV4": "IP", "IPV6": "IP",
    "DOMAIN": "DOMAIN", "HOSTNAME": "DOMAIN",
    "URL": "URL", "URI": "URL",
    "EMAIL": "EMAIL", "EMAIL_ADDRESS": "EMAIL",
    "HASH": "HASH", "MD5": "HASH", "SHA1": "HASH", "SHA-1": "HASH",
    "SHA256": "HASH", "SHA-256": "HASH",
}
VALUE_KEYS = ("indicator", "value", "ioc", "ip", "ip_address", "domain", "url", "email", "hash")
TYPE_KEYS = ("type", "indicator_type", "ioc_type")

def _add(results, kind, value, source, rejected):
    try:
        canonical = normalize_ioc(kind, value)
        results.add((kind, canonical, source))
    except (ValueError, UnicodeError) as exc:
        rejected.append({"value": str(value), "type": kind, "reason": str(exc), "source": source})

def parse_text(text, source):
    results, rejected = set(), []
    # Structured patterns first; remove their spans before generic domain extraction.
    masked = text
    for kind in ("URL", "EMAIL", "HASH", "IP"):
        for match in PATTERNS[kind].finditer(text):
            value = match.group(0).rstrip(".,;)]}")
            _add(results, kind, value, source, rejected)
            masked = masked.replace(match.group(0), " ")
    for match in PATTERNS["DOMAIN"].finditer(masked):
        _add(results, "DOMAIN", match.group(0), source, rejected)
    return results, rejected

def _records_from_json(obj):
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        for key in ("indicators", "iocs", "results", "data", "objects"):
            if isinstance(obj.get(key), list):
                return [x for x in obj[key] if isinstance(x, dict)]
        return [obj]
    raise ValueError("JSON feed must contain an object or array of objects")

def parse_upload(filename, raw_bytes, source=None):
    """Returns (set of (type, canonical_value, source), rejection list)."""
    source = source or filename
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("feed must be UTF-8 text") from exc

    results, rejected = set(), []
    if suffix == "txt":
        return parse_text(text, source)
    if suffix == "json":
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed JSON: {exc.msg}") from exc
        records = _records_from_json(obj)
        for record in records:
            normalized_keys = {str(k).strip().lower(): v for k, v in record.items()}
            raw_type = next((normalized_keys[k] for k in TYPE_KEYS if normalized_keys.get(k)), None)
            raw_value = next((normalized_keys[k] for k in VALUE_KEYS if normalized_keys.get(k)), None)
            if raw_type and raw_value:
                kind = TYPE_ALIASES.get(str(raw_type).upper())
                if not kind:
                    rejected.append({"value": str(raw_value), "type": str(raw_type), "reason": "unsupported type", "source": source})
                else:
                    _add(results, kind, str(raw_value), source, rejected)
            else:
                found, bad = parse_text(json.dumps(record), source)
                results.update(found)
                rejected.extend(bad)
        return results, rejected
    if suffix == "csv":
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValueError("CSV must include a header row")
        for record in reader:
            normalized_keys = {str(k).strip().lower(): v for k, v in record.items() if k}
            raw_type = next((normalized_keys[k] for k in TYPE_KEYS if normalized_keys.get(k)), None)
            raw_value = next((normalized_keys[k] for k in VALUE_KEYS if normalized_keys.get(k)), None)
            if raw_type and raw_value:
                kind = TYPE_ALIASES.get(str(raw_type).upper())
                if kind:
                    _add(results, kind, str(raw_value), source, rejected)
                else:
                    rejected.append({"value": str(raw_value), "type": str(raw_type), "reason": "unsupported type", "source": source})
            else:
                found, bad = parse_text(" ".join(str(v or "") for v in record.values()), source)
                results.update(found)
                rejected.extend(bad)
        return results, rejected
    raise ValueError("supported formats are CSV, TXT and JSON")
