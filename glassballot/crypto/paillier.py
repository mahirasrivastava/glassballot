"""Paillier cryptosystem with g = n + 1.

    KeyGen : n = p*q, lambda = lcm(p-1, q-1), mu = lambda^-1 mod n
    Enc    : c = g^m * r^n mod n^2 = (1 + m*n) * r^n mod n^2,   r in Z_n^*
    Dec    : m = L(c^lambda mod n^2) * mu mod n,   L(x) = (x - 1) / n
    Add    : Enc(m1, r1) * Enc(m2, r2) = Enc(m1 + m2, r1*r2)  (mod n^2)

Randomness recovery (needed for the decryption proof): if c encrypts m then
u = c * g^-m = r^n mod n^2, and r = (u mod n)^(n^-1 mod phi(n)) mod n.
This requires gcd(n, phi(n)) = 1, which key generation enforces.
"""

from dataclasses import dataclass
from functools import cached_property
from math import gcd

from .encoding import hex_to_int, int_to_hex
from .numtheory import is_unit, lcm, modinv, random_prime, random_unit


@dataclass(frozen=True)
class PaillierPublicKey:
    n: int

    @property
    def n2(self) -> int:
        return self.n * self.n

    @property
    def g(self) -> int:
        return self.n + 1

    def g_pow(self, m: int) -> int:
        """g^m mod n^2 = 1 + m*n (binomial theorem); works for negative m."""
        return (1 + (m % self.n) * self.n) % self.n2

    def encrypt(self, m: int, r: int = None):
        """Return (ciphertext, r). Caller keeps r when a proof is needed."""
        if not isinstance(m, int) or not 0 <= m < self.n:
            raise ValueError("plaintext out of range [0, n)")
        if r is None:
            r = random_unit(self.n)
        elif not is_unit(r, self.n, self.n):
            raise ValueError("randomness must be in Z_n^*")
        c = self.g_pow(m) * pow(r, self.n, self.n2) % self.n2
        return c, r

    def add(self, c1: int, c2: int) -> int:
        return c1 * c2 % self.n2

    def sum(self, ciphertexts) -> int:
        """Homomorphic sum. The empty sum is 1 = Enc(0, r=1)."""
        acc = 1
        for c in ciphertexts:
            acc = acc * c % self.n2
        return acc

    def is_valid_ciphertext(self, c) -> bool:
        return is_unit(c, self.n2, self.n)

    def to_dict(self) -> dict:
        return {"n": int_to_hex(self.n)}

    @classmethod
    def from_dict(cls, d: dict) -> "PaillierPublicKey":
        return cls(hex_to_int(d["n"]))


@dataclass(frozen=True)
class PaillierPrivateKey:
    public: PaillierPublicKey
    p: int
    q: int

    @cached_property
    def lam(self) -> int:
        return lcm(self.p - 1, self.q - 1)

    @cached_property
    def mu(self) -> int:
        # With g = n+1, L(g^lambda mod n^2) = lambda mod n.
        return modinv(self.lam, self.public.n)

    @cached_property
    def _n_inv_mod_phi(self) -> int:
        return modinv(self.public.n, (self.p - 1) * (self.q - 1))

    def decrypt(self, c: int) -> int:
        pk = self.public
        if not pk.is_valid_ciphertext(c):
            raise ValueError("invalid ciphertext")
        x = pow(c, self.lam, pk.n2)
        return (x - 1) // pk.n * self.mu % pk.n

    def recover_randomness(self, c: int, m: int) -> int:
        """Return r with c = g^m * r^n mod n^2, or raise if c does not encrypt m."""
        pk = self.public
        u = c * pk.g_pow(-m) % pk.n2
        r = pow(u % pk.n, self._n_inv_mod_phi, pk.n)
        if pow(r, pk.n, pk.n2) != u:
            raise ValueError("ciphertext does not encrypt the claimed plaintext")
        return r


def generate_keypair(bits: int = 2048):
    """Return (public, private) with n of exactly `bits` bits."""
    half = bits // 2
    while True:
        p, q = random_prime(half), random_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits or gcd(n, (p - 1) * (q - 1)) != 1:
            continue
        pub = PaillierPublicKey(n)
        return pub, PaillierPrivateKey(pub, p, q)
