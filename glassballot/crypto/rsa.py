"""RSA signatures, RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017), from scratch.

    KeyGen : n = p*q, e = 65537, d = e^-1 mod lcm(p-1, q-1)
    Sign   : s = EM^d mod n   (computed with CRT)
    Verify : EM' = s^e mod n, accept iff EM' == EMSA-PKCS1-v1_5(message)

Used for (a) the election authority signing voter credentials and
(b) voters signing their ballots.
"""

import hashlib
import hmac
from dataclasses import dataclass
from functools import cached_property
from math import gcd

from .encoding import hash_obj, hex_to_int, int_to_hex
from .numtheory import lcm, modinv, random_prime

PUBLIC_EXPONENT = 65537
# DER prefix of DigestInfo for SHA-256 (RFC 8017, section 9.2, note 1).
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa_pkcs1_v15(message: bytes, k: int) -> bytes:
    t = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        raise ValueError("RSA modulus too short for SHA-256 PKCS#1 v1.5")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int = PUBLIC_EXPONENT

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def verify(self, message: bytes, signature: int) -> bool:
        if not isinstance(signature, int) or not 0 <= signature < self.n:
            return False
        k = self.size_bytes
        try:
            expected = _emsa_pkcs1_v15(message, k)
        except ValueError:
            return False
        actual = pow(signature, self.e, self.n).to_bytes(k, "big")
        return hmac.compare_digest(actual, expected)

    def to_dict(self) -> dict:
        return {"n": int_to_hex(self.n), "e": int_to_hex(self.e)}

    @classmethod
    def from_dict(cls, d: dict) -> "RSAPublicKey":
        return cls(hex_to_int(d["n"]), hex_to_int(d["e"]))

    def fingerprint(self) -> str:
        """SHA-256 of the canonical public key; used as the voter credential ID."""
        return hash_obj(self.to_dict())


@dataclass(frozen=True)
class RSAPrivateKey:
    public: RSAPublicKey
    d: int
    p: int
    q: int

    @cached_property
    def _crt(self):
        return self.d % (self.p - 1), self.d % (self.q - 1), modinv(self.q, self.p)

    def sign(self, message: bytes) -> int:
        n = self.public.n
        em = int.from_bytes(_emsa_pkcs1_v15(message, self.public.size_bytes), "big")
        dp, dq, q_inv = self._crt
        m1, m2 = pow(em, dp, self.p), pow(em, dq, self.q)
        s = m2 + (q_inv * (m1 - m2) % self.p) * self.q
        if pow(s, self.public.e, n) != em:  # guard against CRT faults
            raise RuntimeError("RSA signature self-check failed")
        return s


def generate_keypair(bits: int = 2048, e: int = PUBLIC_EXPONENT):
    """Return (public, private)."""
    half = bits // 2
    while True:
        p, q = random_prime(half), random_prime(bits - half)
        if p == q or gcd(e, p - 1) != 1 or gcd(e, q - 1) != 1:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        d = modinv(e, lcm(p - 1, q - 1))
        pub = RSAPublicKey(n, e)
        return pub, RSAPrivateKey(pub, d, p, q)
