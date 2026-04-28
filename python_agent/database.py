"""
Local SQLite database for Aghora analysis sessions.
No external dependencies — uses Python's built-in sqlite3.
Database file is stored alongside this script.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

DB_PATH = Path(__file__).parent / "aghora.db"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL") # safe concurrent reads
    return conn


def init_db():
    """Create tables on first run."""
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id              TEXT PRIMARY KEY,
                file_name       TEXT NOT NULL,
                file_size       INTEGER DEFAULT 0,
                sha256_hash     TEXT,
                threat_level    TEXT DEFAULT 'unknown',
                threat_summary  TEXT,
                key_findings    TEXT DEFAULT '[]',   -- JSON array
                iocs            TEXT DEFAULT '{}',   -- JSON object
                behavioral      TEXT,
                recommendations TEXT DEFAULT '[]',   -- JSON array
                log_directory   TEXT,
                status          TEXT DEFAULT 'completed',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_created
            ON sessions (created_at DESC)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                sender      TEXT NOT NULL CHECK(sender IN ('user', 'ai')),
                content     TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_chat_session
            ON chat_messages (session_id, created_at ASC)
        """)
    print(f"[DB] SQLite database ready: {DB_PATH}")


# ── CRUD ──────────────────────────────────────────────────────────────────────

def save_session(session_id: str, analysis_results: Dict[str, Any]) -> None:
    """Persist a completed analysis to the database."""
    now = datetime.now().isoformat()

    # Pull data from the nested result structure
    tool_results = analysis_results.get("tool_results", {})
    ai = analysis_results.get("ai_analysis", {})
    file_info = tool_results.get("tools", {}).get("fileinfo", {}).get("data", {})

    file_name   = file_info.get("file_name") or os.path.basename(analysis_results.get("file_path", "unknown"))
    file_size   = file_info.get("file_size", 0)
    sha256_hash = file_info.get("sha256", "")

    threat_level   = ai.get("threat_level", "unknown")
    threat_summary = ai.get("threat_summary", "")
    behavioral     = ai.get("behavioral_analysis", "")
    key_findings   = json.dumps(ai.get("key_findings", []))
    iocs           = json.dumps(ai.get("iocs", {}))
    recommendations = json.dumps(ai.get("recommendations", []))
    log_directory  = analysis_results.get("log_directory", "")

    with get_conn() as conn:
        conn.execute("""
            INSERT INTO sessions
                (id, file_name, file_size, sha256_hash, threat_level, threat_summary,
                 key_findings, iocs, behavioral, recommendations, log_directory,
                 status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                threat_level    = excluded.threat_level,
                threat_summary  = excluded.threat_summary,
                key_findings    = excluded.key_findings,
                iocs            = excluded.iocs,
                behavioral      = excluded.behavioral,
                recommendations = excluded.recommendations,
                status          = 'completed',
                updated_at      = excluded.updated_at
        """, (
            session_id, file_name, file_size, sha256_hash,
            threat_level, threat_summary, key_findings, iocs, behavioral,
            recommendations, log_directory, now, now,
        ))
    print(f"[DB] Session saved: {session_id} ({file_name})")


def list_sessions(limit: int = 100) -> List[Dict[str, Any]]:
    """Return all sessions newest-first."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Return a single session or None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def rename_session(session_id: str, new_name: str) -> bool:
    """Rename the file_name label for a session. Returns True if found."""
    now = datetime.now().isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE sessions SET file_name = ?, updated_at = ? WHERE id = ?",
            (new_name, now, session_id),
        )
    return cur.rowcount > 0


def delete_session(session_id: str) -> bool:
    """Delete a session record and its chat history. Returns True if found."""
    with get_conn() as conn:
        conn.execute("DELETE FROM chat_messages WHERE session_id = ?", (session_id,))
        cur = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
    return cur.rowcount > 0


# ── Chat history ──────────────────────────────────────────────────────────────

def save_chat_message(session_id: str, sender: str, content: str) -> None:
    """Persist a single chat message (sender = 'user' or 'ai')."""
    now = datetime.now().isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO chat_messages (session_id, sender, content, created_at) VALUES (?, ?, ?, ?)",
            (session_id, sender, content, now),
        )


def get_chat_history(session_id: str) -> List[Dict[str, Any]]:
    """Return all chat messages for a session in chronological order."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, session_id, sender, content, created_at FROM chat_messages "
            "WHERE session_id = ? ORDER BY created_at ASC",
            (session_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    # Deserialise JSON columns
    for col in ("key_findings", "recommendations"):
        try:
            d[col] = json.loads(d.get(col) or "[]")
        except Exception:
            d[col] = []
    try:
        d["iocs"] = json.loads(d.get("iocs") or "{}")
    except Exception:
        d["iocs"] = {}
    return d
