"""Fiat-Shamir transform: interactive verifier challenge -> hash of the transcript.

e = first 128 bits of SHA-256(canonical_json({domain, transcript})).

The transcript must contain the public key, the statement, the prover's
commitments and a context (election ID, credential ID, candidate index).
Binding the context is what stops a ballot+proof being replayed by another
voter or in another election.

128-bit challenges are far smaller than the primes p, q of the Paillier
modulus, which the special-soundness argument for n-th-root proofs needs
(e1 - e2 must be invertible mod n).
"""

import hashlib

from .encoding import canonical_json

CHALLENGE_BITS = 128
CHALLENGE_MODULUS = 1 << CHALLENGE_BITS

# Domain-separation tags: one per proof type, so a proof of one kind can
# never be accepted as a proof of another.
DOMAIN_BINARY = "glassballot/v1/ballot-choice-is-0-or-1"
DOMAIN_SUM = "glassballot/v1/ballot-sum-is-1"
DOMAIN_DECRYPTION = "glassballot/v1/correct-decryption"


def challenge(domain: str, transcript: dict) -> int:
    digest = hashlib.sha256(canonical_json({"domain": domain, "transcript": transcript})).digest()
    return int.from_bytes(digest[: CHALLENGE_BITS // 8], "big")
