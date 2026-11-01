"""Transparent demo risk heuristic. Scores are triage hints, not verdicts."""
BASE_SCORES = {"IP": 20, "DOMAIN": 25, "URL": 30, "EMAIL": 15, "HASH": 20}

def score_indicator(kind, distinct_source_count):
    if distinct_source_count < 1:
        raise ValueError("distinct_source_count must be at least 1")
    base = BASE_SCORES.get(kind.upper())
    if base is None:
        raise ValueError(f"unsupported IOC type: {kind}")
    return min(100, base + 20 * (distinct_source_count - 1))

def severity(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"
