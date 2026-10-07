"""M2/M3 - Ballot encryption and well-formedness proofs.

A ballot for k candidates is a one-hot vector, each entry encrypted
separately under Paillier:

    c_i = Enc(m_i, r_i),  m_i in {0, 1},  sum m_i = 1

Proofs attached:
  * choice_proofs[i] : OR-proof that c_i encrypts 0 or 1
  * sum_proof        : proof that prod c_i encrypts exactly 1

Every proof's Fiat-Shamir context contains the election ID and the voter's
credential ID, so a ballot copied under another credential fails to verify.
"""

from ..crypto.encoding import canonical_json, hash_obj, hex_to_int, int_to_hex
from ..crypto.paillier import PaillierPublicKey
from ..crypto.proofs import prove_sum, verify_sum
from ..crypto.sigma import prove_binary, verify_binary


class InvalidBallot(Exception):
    """Raised with a human-readable reason when a ballot must be rejected."""


def choice_context(election_id: str, credential_id: str, index: int) -> dict:
    return {"election_id": election_id, "credential_id": credential_id, "candidate": index}


def sum_context(election_id: str, credential_id: str, ciphertexts_hex) -> dict:
    return {
        "election_id": election_id,
        "credential_id": credential_id,
        "ciphertexts_hash": hash_obj(list(ciphertexts_hex)),
    }


def encrypt_ballot(pk: PaillierPublicKey, election_id: str, credential_id: str,
                   num_candidates: int, choice: int) -> dict:
    """Build the (unsigned) ballot body for `choice` in [0, num_candidates)."""
    if not 0 <= choice < num_candidates:
        raise ValueError("choice out of range")
    ciphertexts, proofs, r_product = [], [], 1
    for i in range(num_candidates):
        m = 1 if i == choice else 0
        c, r = pk.encrypt(m)
        proofs.append(prove_binary(pk, c, m, r, choice_context(election_id, credential_id, i)))
        ciphertexts.append(c)
        r_product = r_product * r % pk.n
    cts_hex = [int_to_hex(c) for c in ciphertexts]
    return {
        "election_id": election_id,
        "credential_id": credential_id,
        "ciphertexts": cts_hex,
        "choice_proofs": proofs,
        "sum_proof": prove_sum(pk, ciphertexts, 1, r_product,
                               sum_context(election_id, credential_id, cts_hex)),
    }


def parse_ciphertexts(body: dict):
    try:
        return [hex_to_int(c) for c in body["ciphertexts"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidBallot(f"malformed ciphertexts: {exc}") from exc


def verify_ballot_body(pk: PaillierPublicKey, election_id: str, num_candidates: int, body: dict) -> None:
    """Check structure and every ZK proof; raise InvalidBallot on failure."""
    if not isinstance(body, dict):
        raise InvalidBallot("ballot body is not an object")
    if body.get("election_id") != election_id:
        raise InvalidBallot("ballot is for a different election")
    credential_id = body.get("credential_id")
    if not isinstance(credential_id, str):
        raise InvalidBallot("missing credential_id")

    ciphertexts = parse_ciphertexts(body)
    proofs = body.get("choice_proofs")
    if len(ciphertexts) != num_candidates or not isinstance(proofs, list) or len(proofs) != num_candidates:
        raise InvalidBallot("wrong number of ciphertexts or proofs")

    for i, (c, proof) in enumerate(zip(ciphertexts, proofs)):
        if not verify_binary(pk, c, proof, choice_context(election_id, credential_id, i)):
            raise InvalidBallot(f"candidate {i}: 0-or-1 proof failed")

    ctx = sum_context(election_id, credential_id, body["ciphertexts"])
    if not isinstance(body.get("sum_proof"), dict) or not verify_sum(pk, ciphertexts, 1, body["sum_proof"], ctx):
        raise InvalidBallot("sum-equals-1 proof failed")


def ballot_signing_bytes(body: dict) -> bytes:
    return canonical_json(body)


def ballot_hash(signed_ballot: dict) -> str:
    """Receipt the voter keeps to find their ballot on the bulletin board."""
    return hash_obj(signed_ballot)
