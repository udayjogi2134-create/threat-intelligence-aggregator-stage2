"""Deterministic correlation helpers."""
def distinct_sources(source_rows):
    return len({str(source).strip() for source in source_rows if str(source).strip()})

def correlate(indicators):
    """Group parsed tuples (type, value, source) by canonical indicator."""
    grouped = {}
    for kind, value, source in indicators:
        key = (kind, value)
        grouped.setdefault(key, set()).add(source)
    return [
        {"type": kind, "value": value, "sources": sorted(sources),
         "source_count": len(sources)}
        for (kind, value), sources in sorted(grouped.items())
    ]
