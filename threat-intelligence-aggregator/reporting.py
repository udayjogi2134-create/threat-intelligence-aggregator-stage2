"""Export filtered indicator records to CSV, JSON and plain-text IOC lists."""
import csv
import io
import json

def to_csv(rows):
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()

def to_json(rows):
    return json.dumps(rows, indent=2, ensure_ascii=False)

def to_txt(rows):
    return "\n".join(row["value"] for row in rows) + ("\n" if rows else "")
