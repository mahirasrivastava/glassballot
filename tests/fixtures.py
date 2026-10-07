"""Shared, cached test keys. Small sizes keep the suite fast; the maths is identical."""

import sys
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from glassballot.crypto import paillier, rsa  # noqa: E402

TEST_PAILLIER_BITS = 512
TEST_RSA_BITS = 768


@lru_cache(maxsize=None)
def paillier_keys():
    return paillier.generate_keypair(TEST_PAILLIER_BITS)


@lru_cache(maxsize=None)
def rsa_keys():
    return rsa.generate_keypair(TEST_RSA_BITS)


def small_election(num_voters=3, candidates=("A", "B", "C")):
    from glassballot.simulation import Election
    return Election(num_voters, candidates, TEST_PAILLIER_BITS, TEST_RSA_BITS, TEST_RSA_BITS)
