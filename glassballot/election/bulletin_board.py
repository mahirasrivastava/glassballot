"""M4 - Append-only, hash-chained public bulletin board.

Stand-in for the PostgreSQL board: a JSON-lines file where each entry is

    {seq, kind, payload, prev_hash, entry_hash}
    entry_hash = SHA-256(canonical({seq, kind, payload, prev_hash}))

Changing, inserting or deleting any entry breaks every later hash, which the
public verifier detects. Entry kinds: election, credential, ballot, close, result.
"""

import copy
import json
from pathlib import Path

from ..crypto.encoding import hash_obj

GENESIS_HASH = "0" * 64
ENTRY_KINDS = ("election", "credential", "ballot", "close", "result")


def compute_entry_hash(seq: int, kind: str, payload: dict, prev_hash: str) -> str:
    return hash_obj({"seq": seq, "kind": kind, "payload": payload, "prev_hash": prev_hash})


def verify_chain(entries) -> tuple:
    """Return (ok, reason)."""
    prev = GENESIS_HASH
    for i, e in enumerate(entries):
        try:
            if e["seq"] != i:
                return False, f"entry {i}: sequence number {e['seq']} out of order"
            if e["kind"] not in ENTRY_KINDS:
                return False, f"entry {i}: unknown kind {e['kind']!r}"
            if e["prev_hash"] != prev:
                return False, f"entry {i}: prev_hash does not match entry {i - 1}"
            if compute_entry_hash(i, e["kind"], e["payload"], e["prev_hash"]) != e["entry_hash"]:
                return False, f"entry {i}: content does not match its hash (tampered)"
        except (KeyError, TypeError):
            return False, f"entry {i}: malformed"
        prev = e["entry_hash"]
    return True, f"{len(entries)} entries, head {prev[:16]}..."


class BulletinBoard:
    def __init__(self, path=None):
        self._entries = []
        self._path = Path(path) if path else None
        if self._path and self._path.exists():
            self._entries = load_entries(self._path)
            ok, reason = verify_chain(self._entries)
            if not ok:
                raise ValueError(f"board file failed chain check: {reason}")

    @property
    def head(self) -> str:
        return self._entries[-1]["entry_hash"] if self._entries else GENESIS_HASH

    def append(self, kind: str, payload: dict) -> dict:
        if kind not in ENTRY_KINDS:
            raise ValueError(f"unknown entry kind {kind!r}")
        seq, prev = len(self._entries), self.head
        payload = copy.deepcopy(payload)
        entry = {"seq": seq, "kind": kind, "payload": payload, "prev_hash": prev,
                 "entry_hash": compute_entry_hash(seq, kind, payload, prev)}
        self._entries.append(entry)
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        return copy.deepcopy(entry)

    def entries(self, kind: str = None) -> list:
        """Read-only copies; callers cannot mutate the board through them."""
        return [copy.deepcopy(e) for e in self._entries if kind is None or e["kind"] == kind]

    def __len__(self):
        return len(self._entries)


def load_entries(path) -> list:
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
