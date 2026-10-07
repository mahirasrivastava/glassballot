"""M5/M6 - Homomorphic tallying and the trustee's proof of correct decryption.

For candidate i, the encrypted tally is the product of every accepted ballot's
i-th ciphertext:  T_i = prod_b c_{b,i} = Enc(sum_b m_{b,i}).
The trustee decrypts each T_i exactly once and proves the decryption is
correct. Individual ballots are never decrypted.
"""

from ..crypto.encoding import hex_to_int, int_to_hex
from ..crypto import paillier
from ..crypto.paillier import PaillierPublicKey
from ..crypto.proofs import prove_decryption


def decryption_context(election_id: str, candidate: int) -> dict:
    return {"election_id": election_id, "candidate": candidate}


def aggregate(pk: PaillierPublicKey, ballot_bodies, num_candidates: int) -> list:
    """Encrypted per-candidate totals from a list of accepted ballot bodies."""
    totals = [1] * num_candidates
    for body in ballot_bodies:
        for i, c_hex in enumerate(body["ciphertexts"]):
            totals[i] = totals[i] * hex_to_int(c_hex) % pk.n2
    return totals


class Trustee:
    """Sole holder of the Paillier private key (threshold decryption = future work)."""

    def __init__(self, paillier_bits: int = 2048):
        self.public_key, self._private_key = paillier.generate_keypair(paillier_bits)

    def decrypt_tally(self, election_id: str, candidates, encrypted_totals) -> list:
        results = []
        for i, (name, c) in enumerate(zip(candidates, encrypted_totals)):
            m = self._private_key.decrypt(c)
            results.append({
                "candidate": i,
                "name": name,
                "encrypted_total": int_to_hex(c),
                "total": m,
                "proof": prove_decryption(self._private_key, c, m, decryption_context(election_id, i)),
            })
        return results
