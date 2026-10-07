"""Non-interactive Sigma protocols over a Paillier modulus.

1. Proof of n-th residuosity (base protocol)
   Statement : u is an n-th residue mod n^2, i.e. u = r^n.  Witness: r.
   Commit    : s <- Z_n^*,  a = s^n mod n^2
   Challenge : e = H(domain, n, context, u, a)           (Fiat-Shamir)
   Response  : z = s * r^e mod n
   Verify    : z^n == a * u^e (mod n^2)
   Why z^n works: (x + kn)^n = x^n (mod n^2), so (s r^e mod n)^n = s^n (r^n)^e.

2. OR-proof that a ciphertext encrypts 0 or 1 (Cramer-Damgard-Schoenmakers)
   u_j = c * g^-j  for j in {0, 1}; c encrypts j  <=>  u_j is an n-th residue.
   The prover runs (1) honestly on the true branch t and simulates the false
   branch f by picking e_f, z_f first and setting a_f = z_f^n * u_f^-e_f.
   Challenge e = H(..., c, a_0, a_1); e_t = e - e_f mod 2^128.
   Verify: e_0 + e_1 = e (mod 2^128) and z_j^n = a_j * u_j^e_j for both j.
   The verifier learns that c encrypts 0 or 1, but not which.
"""

import secrets

from .encoding import hex_to_int, int_to_hex
from .fiat_shamir import CHALLENGE_MODULUS, DOMAIN_BINARY, challenge
from .numtheory import is_unit, random_unit
from .paillier import PaillierPublicKey


class ProofFormatError(ValueError):
    pass


def _transcript(pk: PaillierPublicKey, context: dict, **elements: int) -> dict:
    t = {"n": int_to_hex(pk.n), "context": context}
    t.update({k: int_to_hex(v) for k, v in elements.items()})
    return t


def _parse(proof: dict, keys) -> dict:
    try:
        return {k: hex_to_int(proof[k]) for k in keys}
    except (KeyError, TypeError, ValueError) as exc:
        raise ProofFormatError(f"malformed proof: {exc}") from exc


# ---------------------------------------------------------------- n-th residue

def prove_nth_residue(pk: PaillierPublicKey, u: int, r: int, context: dict, domain: str) -> dict:
    n, n2 = pk.n, pk.n2
    if pow(r, n, n2) != u % n2:
        raise ValueError("witness r does not satisfy u = r^n mod n^2")
    s = random_unit(n)
    a = pow(s, n, n2)
    e = challenge(domain, _transcript(pk, context, u=u, a=a))
    z = s * pow(r, e, n) % n
    return {"a": int_to_hex(a), "z": int_to_hex(z)}


def verify_nth_residue(pk: PaillierPublicKey, u: int, proof: dict, context: dict, domain: str) -> bool:
    n, n2 = pk.n, pk.n2
    try:
        v = _parse(proof, ("a", "z"))
    except ProofFormatError:
        return False
    a, z = v["a"], v["z"]
    if not (is_unit(u, n2, n) and is_unit(a, n2, n) and is_unit(z, n, n)):
        return False
    e = challenge(domain, _transcript(pk, context, u=u, a=a))
    return pow(z, n, n2) == a * pow(u, e, n2) % n2


# --------------------------------------------------------- 0-or-1 OR-proof

def prove_binary(pk: PaillierPublicKey, c: int, m: int, r: int, context: dict) -> dict:
    n, n2 = pk.n, pk.n2
    if m not in (0, 1):
        raise ValueError("binary proof only for m in {0, 1}")
    if pk.g_pow(m) * pow(r, n, n2) % n2 != c:
        raise ValueError("(m, r) is not an opening of c")

    u = [c * pk.g_pow(-j) % n2 for j in (0, 1)]
    t, f = m, 1 - m
    a, e_parts, z = [0, 0], [0, 0], [0, 0]

    # Simulated (false) branch.
    e_parts[f] = secrets.randbelow(CHALLENGE_MODULUS)
    z[f] = random_unit(n)
    a[f] = pow(z[f], n, n2) * pow(u[f], -e_parts[f], n2) % n2

    # Real (true) branch commitment.
    s = random_unit(n)
    a[t] = pow(s, n, n2)

    e = challenge(DOMAIN_BINARY, _transcript(pk, context, c=c, a0=a[0], a1=a[1]))
    e_parts[t] = (e - e_parts[f]) % CHALLENGE_MODULUS
    z[t] = s * pow(r, e_parts[t], n) % n

    return {
        "a0": int_to_hex(a[0]), "a1": int_to_hex(a[1]),
        "e0": int_to_hex(e_parts[0]), "e1": int_to_hex(e_parts[1]),
        "z0": int_to_hex(z[0]), "z1": int_to_hex(z[1]),
    }


def verify_binary(pk: PaillierPublicKey, c: int, proof: dict, context: dict) -> bool:
    n, n2 = pk.n, pk.n2
    if not pk.is_valid_ciphertext(c):
        return False
    try:
        v = _parse(proof, ("a0", "a1", "e0", "e1", "z0", "z1"))
    except ProofFormatError:
        return False
    a, e_parts, z = (v["a0"], v["a1"]), (v["e0"], v["e1"]), (v["z0"], v["z1"])
    if not all(is_unit(x, n2, n) for x in a) or not all(is_unit(x, n, n) for x in z):
        return False
    if not all(0 <= x < CHALLENGE_MODULUS for x in e_parts):
        return False
    e = challenge(DOMAIN_BINARY, _transcript(pk, context, c=c, a0=a[0], a1=a[1]))
    if (e_parts[0] + e_parts[1]) % CHALLENGE_MODULUS != e:
        return False
    for j in (0, 1):
        u_j = c * pk.g_pow(-j) % n2
        if pow(z[j], n, n2) != a[j] * pow(u_j, e_parts[j], n2) % n2:
            return False
    return True
