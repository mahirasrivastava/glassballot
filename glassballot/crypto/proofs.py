"""Application-level ZK statements built on the n-th residue Sigma protocol.

Sum proof (ballot encodes exactly one vote)
    C = prod c_i encrypts sum m_i with randomness R = prod r_i (mod n).
    "sum m_i = k"  <=>  C * g^-k = R^n  -> prove n-th residuosity with witness R.

Decryption proof (tally announced correctly) -- the Paillier analogue of
Chaum-Pedersen:
    "C decrypts to m"  <=>  C * g^-m = R^n. The trustee does not know R, but
    recovers it with the private key (PaillierPrivateKey.recover_randomness)
    and proves n-th residuosity. Anyone can verify with the public key only;
    R itself is never revealed.
"""

from .fiat_shamir import DOMAIN_DECRYPTION, DOMAIN_SUM
from .paillier import PaillierPrivateKey, PaillierPublicKey
from .sigma import prove_nth_residue, verify_nth_residue


def prove_sum(pk: PaillierPublicKey, ciphertexts, total: int, r_product: int, context: dict) -> dict:
    u = pk.sum(ciphertexts) * pk.g_pow(-total) % pk.n2
    return prove_nth_residue(pk, u, r_product, context, DOMAIN_SUM)


def verify_sum(pk: PaillierPublicKey, ciphertexts, total: int, proof: dict, context: dict) -> bool:
    u = pk.sum(ciphertexts) * pk.g_pow(-total) % pk.n2
    return verify_nth_residue(pk, u, proof, context, DOMAIN_SUM)


def prove_decryption(sk: PaillierPrivateKey, c: int, m: int, context: dict) -> dict:
    pk = sk.public
    r = sk.recover_randomness(c, m)
    u = c * pk.g_pow(-m) % pk.n2
    return prove_nth_residue(pk, u, r, context, DOMAIN_DECRYPTION)


def verify_decryption(pk: PaillierPublicKey, c: int, m: int, proof: dict, context: dict) -> bool:
    if not isinstance(m, int) or not 0 <= m < pk.n or not pk.is_valid_ciphertext(c):
        return False
    u = c * pk.g_pow(-m) % pk.n2
    return verify_nth_residue(pk, u, proof, context, DOMAIN_DECRYPTION)
