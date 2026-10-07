"""Number-theory primitives shared by Paillier and RSA.

Everything here uses Python's arbitrary-precision ints and the `secrets`
CSPRNG. pow(x, -1, m) (Python >= 3.8) gives modular inverses.
"""

import secrets
from math import gcd

MILLER_RABIN_ROUNDS = 32


def _sieve(limit: int) -> tuple:
    flags = bytearray([1]) * (limit + 1)
    flags[0] = flags[1] = 0
    for i in range(2, int(limit ** 0.5) + 1):
        if flags[i]:
            flags[i * i :: i] = bytearray(len(flags[i * i :: i]))
    return tuple(i for i, f in enumerate(flags) if f)


SMALL_PRIMES = _sieve(2000)


def is_probable_prime(n: int, rounds: int = MILLER_RABIN_ROUNDS) -> bool:
    """Miller-Rabin with trial division by small primes first."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits: int) -> int:
    """Random prime of exactly `bits` bits; top two bits set so p*q has 2*bits bits."""
    if bits < 16:
        raise ValueError("prime size too small")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(candidate):
            return candidate


def lcm(a: int, b: int) -> int:
    return a // gcd(a, b) * b


def modinv(a: int, m: int) -> int:
    return pow(a, -1, m)


def random_unit(n: int) -> int:
    """Uniform element of Z_n^* (1 <= r < n, gcd(r, n) = 1)."""
    while True:
        r = secrets.randbelow(n - 1) + 1
        if gcd(r, n) == 1:
            return r


def is_unit(x: int, modulus: int, n: int) -> bool:
    """True if 0 < x < modulus and x is invertible mod n (hence mod n^2)."""
    return isinstance(x, int) and 0 < x < modulus and gcd(x, n) == 1
