"""Canonical serialisation and hashing.

Rule used everywhere in the project: big integers are stored as lowercase hex
strings (no 0x prefix); small counters/indices may be plain JSON ints. Hashes
are SHA-256 over canonical JSON (sorted keys, no whitespace). A future JS
voting booth must reproduce exactly this encoding.
"""

import hashlib
import json


def int_to_hex(x: int) -> str:
    if not isinstance(x, int) or x < 0:
        raise ValueError("only non-negative ints are encoded")
    return format(x, "x")


def hex_to_int(s: str) -> int:
    if not isinstance(s, str) or not s or any(ch not in "0123456789abcdef" for ch in s):
        raise ValueError(f"malformed hex integer: {s!r}")
    return int(s, 16)


def canonical_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj) -> str:
    return sha256_hex(canonical_json(obj))
