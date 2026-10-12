"""
SQLite storage. Stores FULL content (never previews) so verification can re-hash.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from .chain import ChainEntry
from .config import DB_PATH


class Storage:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        with self._conn() as c:
            cur = c.cursor()

            cur.execute("""
                CREATE TABLE IF NOT EXISTS entries (
                    entry_index     INTEGER NOT NULL,
                    device_id       TEXT    NOT NULL DEFAULT 'dev-1',
                    timestamp       TEXT    NOT NULL,
                    tier            TEXT    NOT NULL,
                    algorithm       TEXT    NOT NULL,
                    content         TEXT    NOT NULL,
                    event_type TEXT,
                leaf_hash       TEXT    NOT NULL,
                    prev_hash       TEXT    NOT NULL,
                    chain_hash      TEXT    NOT NULL,
                    PRIMARY KEY (device_id, entry_index)
                )
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_chain_hash
                ON entries(chain_hash)
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id           TEXT    NOT NULL,
                    segment_start       INTEGER NOT NULL,
                    segment_end         INTEGER NOT NULL,
                    chain_start         TEXT    NOT NULL,
                    chain_end           TEXT    NOT NULL,
                    timestamp           TEXT    NOT NULL,
                    prev_digest         TEXT    NOT NULL,
                    checkpoint_digest   TEXT    NOT NULL,
                    segment_digest      TEXT    NOT NULL DEFAULT '',
                    batch_digest        TEXT
                )
            """)

            c.commit()

    # ─── Entries ──────────────────────────────────────────
    def insert_entry(self, entry: ChainEntry, device_id: str = "dev-1") -> None:
        with self._conn() as c:
            c.execute("""
                INSERT OR REPLACE INTO entries
                (entry_index, device_id, timestamp, tier, algorithm, content,
                 leaf_hash, prev_hash, chain_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.index, device_id, entry.timestamp, entry.tier,
                entry.algorithm, entry.content,
                entry.leaf_hash_hex, entry.prev_hash_hex, entry.chain_hash_hex,
            ))
            c.commit()

    def insert_entries_batch(self, entries, device_id: str = "dev-1") -> None:
        """Accept both ChainEntry objects and dicts."""
        def _unpack(e):
            if isinstance(e, dict):
                return (
                    e["entry_index"],
                    device_id or e.get("device_id"),
                    e["timestamp"],
                    e["tier"],
                    e["algorithm"],
                    e["content"],
                    e.get("event_type", "unknown"),
                    e["leaf_hash"],
                    e["prev_hash"],
                    e["chain_hash"],
                )
            return (
                e.index, device_id, e.timestamp, e.tier, e.algorithm,
                e.content, getattr(e, "event_type", "unknown"),
                e.leaf_hash_hex, e.prev_hash_hex, e.chain_hash_hex,
            )

        with self._conn() as c:
            c.executemany("""
                INSERT OR REPLACE INTO entries
                (entry_index, device_id, timestamp, tier, algorithm, content,
                 event_type, leaf_hash, prev_hash, chain_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [_unpack(e) for e in entries])
            c.commit()

    def get_entry(self, index: int, device_id: str = "dev-1") -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM entries WHERE device_id = ? AND entry_index = ?",
                (device_id, index),
            ).fetchone()
            return dict(row) if row else None


    def insert_entries_large_batch(self, entries, device_id=None, batch_size=10_000):
        """
        Insert entries in transactions of batch_size rows.
        A single commit per batch, rather than per entry.
        Accepts both ChainEntry objects and dicts.
        """
        import sqlite3 as _sqlite3

        def _unpack(e):
            if isinstance(e, dict):
                return (
                    e["entry_index"], device_id or e.get("device_id"),
                    e["timestamp"], e["tier"], e["algorithm"],
                    e["content"],
                    e.get("event_type", "unknown"),
                    e["leaf_hash"], e["prev_hash"], e["chain_hash"],
                )
            return (
                e.index, device_id, e.timestamp, e.tier, e.algorithm,
                e.content, getattr(e, "event_type", "unknown"),
                e.leaf_hash_hex, e.prev_hash_hex, e.chain_hash_hex,
            )

        rows = [_unpack(e) for e in entries]
        conn = _sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            for start in range(0, len(rows), batch_size):
                chunk = rows[start:start + batch_size]
                conn.execute("BEGIN")
                conn.executemany("""
                    INSERT OR REPLACE INTO entries
                    (entry_index, device_id, timestamp, tier, algorithm,
                     content, event_type, leaf_hash, prev_hash, chain_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, chunk)
                conn.commit()
        finally:
            conn.close()

    def get_entries_between(self, start: int, end: int, device_id: str = "dev-1") -> List[Dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT * FROM entries
                WHERE device_id = ? AND entry_index BETWEEN ? AND ?
                ORDER BY entry_index ASC
            """, (device_id, start, end)).fetchall()
            return [dict(r) for r in rows]

    def last_entry(self, device_id: str = "dev-1") -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute("""
                SELECT * FROM entries
                WHERE device_id = ?
                ORDER BY entry_index DESC LIMIT 1
            """, (device_id,)).fetchone()
            return dict(row) if row else None

    def count_entries(self, device_id: str = "dev-1") -> int:
        with self._conn() as c:
            return c.execute(
                "SELECT COUNT(*) FROM entries WHERE device_id = ?",
                (device_id,),
            ).fetchone()[0]

    # ─── Checkpoints ──────────────────────────────────────
    def insert_checkpoint(self, cp: Dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute("""
                INSERT INTO checkpoints
                (device_id, segment_start, segment_end, chain_start,
                 chain_end, timestamp, prev_digest, checkpoint_digest,
                 segment_digest)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cp["device_id"], cp["segment_start"], cp["segment_end"],
                cp["chain_start"], cp["chain_end"], cp["timestamp"],
                cp["prev_digest"], cp["checkpoint_digest"],
                cp.get("segment_digest", ""),
            ))
            c.commit()

    def last_checkpoint(self, device_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute("""
                SELECT * FROM checkpoints
                WHERE device_id = ?
                ORDER BY seq DESC LIMIT 1
            """, (device_id,)).fetchone()
            return dict(row) if row else None
