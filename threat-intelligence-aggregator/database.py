"""SQLite persistence with source provenance and feed-run audit records."""
import sqlite3
from datetime import datetime, timezone
from config import DB_PATH, DATA_DIR
from risk_engine import score_indicator

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            UNIQUE(type, value)
        );
        CREATE TABLE IF NOT EXISTS indicator_sources (
            indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY(indicator_id, source)
        );
        CREATE TABLE IF NOT EXISTS feed_runs (
            id INTEGER PRIMARY KEY,
            source TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            status TEXT NOT NULL,
            accepted_count INTEGER NOT NULL,
            rejected_count INTEGER NOT NULL,
            error TEXT
        );
        CREATE TABLE IF NOT EXISTS rejections (
            id INTEGER PRIMARY KEY,
            feed_run_id INTEGER NOT NULL REFERENCES feed_runs(id) ON DELETE CASCADE,
            value TEXT,
            type TEXT,
            reason TEXT NOT NULL
        );
        """)

def record_feed_run(source, status, accepted_count, rejected, error=None):
    now = utc_now()
    with connect() as con:
        cur = con.execute("""INSERT INTO feed_runs
            (source, started_at, finished_at, status, accepted_count, rejected_count, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (source, now, now, status, accepted_count, len(rejected), error))
        run_id = cur.lastrowid
        con.executemany("""INSERT INTO rejections(feed_run_id,value,type,reason)
            VALUES(?,?,?,?)""",
            [(run_id, r.get("value"), r.get("type"), r.get("reason", "rejected")) for r in rejected])
        return run_id

def upsert_indicators(items):
    """items is an iterable of (type, canonical value, source)."""
    now = utc_now()
    grouped = {}
    for kind, value, source in items:
        grouped.setdefault((kind, value), set()).add(source)
    with connect() as con:
        for (kind, value), sources in grouped.items():
            con.execute("""INSERT INTO indicators(type,value,first_seen,last_seen,risk_score)
                VALUES(?,?,?,?,?)
                ON CONFLICT(type,value) DO UPDATE SET last_seen=excluded.last_seen""",
                (kind, value, now, now, 0))
            row = con.execute("SELECT id, first_seen FROM indicators WHERE type=? AND value=?",
                              (kind, value)).fetchone()
            indicator_id = row["id"]
            for source in sources:
                con.execute("""INSERT INTO indicator_sources(indicator_id,source,first_seen,last_seen)
                    VALUES(?,?,?,?)
                    ON CONFLICT(indicator_id,source) DO UPDATE SET last_seen=excluded.last_seen""",
                    (indicator_id, source, now, now))
            source_count = con.execute(
                "SELECT COUNT(*) FROM indicator_sources WHERE indicator_id=?", (indicator_id,)
            ).fetchone()[0]
            con.execute("UPDATE indicators SET risk_score=? WHERE id=?",
                        (score_indicator(kind, source_count), indicator_id))

def list_indicators():
    with connect() as con:
        rows = con.execute("""
            SELECT i.type, i.value, i.risk_score, i.first_seen, i.last_seen,
                   GROUP_CONCAT(s.source, ' | ') AS sources,
                   COUNT(s.source) AS source_count
            FROM indicators i LEFT JOIN indicator_sources s ON s.indicator_id=i.id
            GROUP BY i.id ORDER BY i.risk_score DESC, i.value
        """).fetchall()
        return [dict(r) for r in rows]

def list_feed_runs(limit=100):
    with connect() as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM feed_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

def list_rejections(limit=200):
    with connect() as con:
        return [dict(r) for r in con.execute("""
            SELECT r.*, f.source, f.started_at FROM rejections r
            JOIN feed_runs f ON f.id=r.feed_run_id
            ORDER BY r.id DESC LIMIT ?""", (limit,)).fetchall()]
