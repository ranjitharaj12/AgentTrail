"""SQLite event store: one row per event.

Simple fields get their own column so they can be queried with SQL.
List/dict fields (args, paths, signals, judge_verdict) are stored as JSON text.
"""
import json
import sqlite3
from pathlib import Path

from agenttrail.schema import Event, Label

JSON_FIELDS = {"args", "paths", "signals", "judge_verdict"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT, project TEXT, event_type TEXT, turn_id TEXT, actor TEXT,
    tool TEXT, tool_source TEXT, mcp_server TEXT, tool_use_id TEXT,
    decision TEXT, permission_mode TEXT, stated_purpose TEXT,
    args TEXT, prompt_text TEXT, content_excerpt TEXT,
    outcome TEXT, result_size INTEGER, response TEXT,
    paths TEXT, path_class TEXT, net_dest TEXT, action_type TEXT,
    trust_level TEXT, intent TEXT,
    signals TEXT, drift_score REAL, judge_verdict TEXT,
    UNIQUE (session_id, seq)
);
CREATE TABLE IF NOT EXISTS labels (
    session_id TEXT PRIMARY KEY,
    malicious INTEGER NOT NULL,
    malicious_event_ids TEXT NOT NULL,
    scenario TEXT, notes TEXT,
    trigger_event_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events (session_id, seq);
"""


def connect(db_path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(labels)")}
    if "trigger_event_id" not in cols:                      # database made before triggers existed
        conn.execute("ALTER TABLE labels ADD COLUMN trigger_event_id TEXT")
    return conn


def _to_row(ev: Event) -> dict:
    row = ev.model_dump(mode="json")  # enums become plain strings
    row["event_id"] = ev.event_id
    for f in JSON_FIELDS:
        row[f] = json.dumps(row[f])
    return row


def save_events(conn: sqlite3.Connection, events: list[Event]) -> None:
    for ev in events:
        row = _to_row(ev)
        cols = ", ".join(row)
        marks = ", ".join(f":{c}" for c in row)
        # REPLACE makes re-loading the same fixture safe (idempotent)
        conn.execute(f"INSERT OR REPLACE INTO events ({cols}) VALUES ({marks})", row)
    conn.commit()


def save_label(conn: sqlite3.Connection, label: Label) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO labels (session_id, malicious, malicious_event_ids, scenario, notes, trigger_event_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (label.session_id, int(label.malicious), json.dumps(label.malicious_event_ids),
         label.scenario, label.notes, label.trigger_event_id),
    )
    conn.commit()


def get_session_events(conn: sqlite3.Connection, session_id: str) -> list[Event]:
    rows = conn.execute(
        "SELECT * FROM events WHERE session_id = ? ORDER BY seq", (session_id,)
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d.pop("event_id")  # computed property, not a stored field
        for f in JSON_FIELDS:
            d[f] = json.loads(d[f])
        out.append(Event(**d))
    return out


def list_sessions(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT session_id, project, COUNT(*) AS n_events, MIN(ts) AS started "
        "FROM events GROUP BY session_id ORDER BY started"
    ).fetchall()
