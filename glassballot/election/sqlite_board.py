"""M4 on SQLite - the bulletin board stored in a database file (stdlib sqlite3).

One file holds the boards of many elections, keyed by board_id. Triggers make
the table append-only: UPDATE and DELETE abort inside the database itself (the
SQLite version of the planned PostgreSQL trigger), and unique indexes allow one
credential entry and one ballot per credential. That is defence in depth,
not the security argument: whoever controls the file can drop the triggers, so
every board is re-checked against its hash chain when it is opened, and the
public verifier re-checks everything anyway.
"""

import json
import secrets
import sqlite3
import threading
from pathlib import Path

from .bulletin_board import BulletinBoard, verify_chain

SCHEMA = """
CREATE TABLE IF NOT EXISTS board_entries (
    board_id    TEXT    NOT NULL,
    seq         INTEGER NOT NULL CHECK (seq >= 0),
    kind        TEXT    NOT NULL,
    payload     TEXT    NOT NULL,              -- canonical JSON (sorted keys)
    prev_hash   TEXT    NOT NULL,
    entry_hash  TEXT    NOT NULL UNIQUE,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (board_id, seq)
);
-- one credential entry and one ballot per credential, enforced by the database too
CREATE UNIQUE INDEX IF NOT EXISTS one_credential_entry ON board_entries
    (board_id, json_extract(payload, '$.credential_id')) WHERE kind = 'credential';
CREATE UNIQUE INDEX IF NOT EXISTS one_ballot_per_credential ON board_entries
    (board_id, json_extract(payload, '$.body.credential_id')) WHERE kind = 'ballot';
CREATE TRIGGER IF NOT EXISTS board_entries_no_update
BEFORE UPDATE ON board_entries
BEGIN SELECT RAISE(ABORT, 'bulletin board is append-only'); END;
CREATE TRIGGER IF NOT EXISTS board_entries_no_delete
BEFORE DELETE ON board_entries
BEGIN SELECT RAISE(ABORT, 'bulletin board is append-only'); END;
"""


def connect(path) -> sqlite3.Connection:
    """Open (creating if needed) a board database. Usable from any thread; callers serialise access."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def load_sqlite_entries(conn: sqlite3.Connection, board_id: str) -> list:
    rows = conn.execute(
        "SELECT seq, kind, payload, prev_hash, entry_hash FROM board_entries WHERE board_id = ? ORDER BY seq",
        (board_id,)).fetchall()
    return [{"seq": seq, "kind": kind, "payload": json.loads(payload), "prev_hash": prev, "entry_hash": h}
            for seq, kind, payload, prev, h in rows]


def list_boards(conn: sqlite3.Connection) -> list:
    """Newest first: board_id, title and election_id (from the election entry), size, head, timestamps."""
    rows = conn.execute("""
        SELECT b.board_id, COUNT(*), MIN(b.created_at), MAX(b.created_at),
               (SELECT payload FROM board_entries WHERE board_id = b.board_id AND seq = 0),
               (SELECT entry_hash FROM board_entries WHERE board_id = b.board_id ORDER BY seq DESC LIMIT 1),
               SUM(b.kind = 'ballot'), SUM(b.kind = 'result')
        FROM board_entries b GROUP BY b.board_id ORDER BY MIN(b.created_at) DESC
    """).fetchall()
    out = []
    for board_id, n, created, updated, first, head, ballots, results in rows:
        election = json.loads(first) if first else {}
        out.append({"board_id": board_id, "title": election.get("title"), "election_id": election.get("election_id"),
                    "entries": n, "ballots": ballots, "tallied": bool(results), "head": head,
                    "created_at": created, "updated_at": updated})
    return out


class SQLiteBoard(BulletinBoard):
    """Same interface as BulletinBoard; entries live in a SQLite table instead of a JSONL file."""

    def __init__(self, conn: sqlite3.Connection, board_id: str = None, lock: threading.Lock = None):
        super().__init__()
        self._conn = conn
        self._lock = lock or threading.Lock()
        self.board_id = board_id or secrets.token_hex(8)
        self._entries = load_sqlite_entries(conn, self.board_id)
        ok, reason = verify_chain(self._entries)
        if not ok:
            raise ValueError(f"board {self.board_id} failed chain check: {reason}")

    def _persist(self, entry: dict):
        with self._lock:
            self._conn.execute(
                "INSERT INTO board_entries (board_id, seq, kind, payload, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (self.board_id, entry["seq"], entry["kind"], json.dumps(entry["payload"], sort_keys=True),
                 entry["prev_hash"], entry["entry_hash"]))
