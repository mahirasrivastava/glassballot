"""M5/M6 - Homomorphic tallying and threshold decryption by k trustees.

Tally. For candidate i the encrypted total is the product of every accepted
ballot's i-th ciphertext:  T_i = prod_b c_{b,i} = Enc(sum_b m_{b,i}, R_i)
with R_i = prod_b r_{b,i} mod n. Individual ballots are never decrypted.

Threshold decryption (k-of-k, trusted dealer).
  * For x in Z_n^*, x^lambda = 1 (mod n). Let e' = n^-1 mod lambda.
  * T = g^m R^n, and g^m = 1 (mod n), so (T mod n)^e' = R^(n e') = R (mod n):
    raising T mod n to e' recovers the randomness of T.
  * The dealer splits e' into k additive shares (e' = sum s_j mod lambda),
    hands one to each trustee and forgets p, q, lambda and e'.
  * Trustee j publishes the partial  P_j = (T mod n)^s_j mod n.
    Anyone multiplies them:  R = prod P_j mod n.
  * The opening (m, R) is checked by anyone with the public key alone:
        R in Z_n^*  and  g^m * R^n = T (mod n^2)
    Since x -> x^n is a bijection on Z_n^* (gcd(n, phi(n)) = 1), at most one
    R fits, so a wrong total or a bad partial cannot pass. Soundness needs no
    extra assumption; it is a direct check, not a proof of knowledge.
  * Fewer than k trustees learn nothing: any k-1 shares are statistically
    independent of e' (shares are drawn from a range 2^128 times larger
    than lambda). All k trustees together could open single ballots, so
    each trustee recomputes T from the bulletin board and only ever
    decrypts those published totals.

Revealing R_i is harmless: it is the product of every ballot's randomness for
that candidate and opens nothing but the published total.
"""

import secrets

from ..crypto import paillier
from ..crypto.encoding import hex_to_int, int_to_hex
from ..crypto.numtheory import is_unit, modinv
from ..crypto.paillier import PaillierPublicKey

SHARE_SLACK_BITS = 128   # statistical hiding of each share


def aggregate(pk: PaillierPublicKey, ballot_bodies, num_candidates: int) -> list:
    """Encrypted per-candidate totals from a list of accepted ballot bodies."""
    totals = [1] * num_candidates
    for body in ballot_bodies:
        for i, c_hex in enumerate(body["ciphertexts"]):
            totals[i] = totals[i] * hex_to_int(c_hex) % pk.n2
    return totals


# ------------------------------------------------------------------ key ceremony
def split_key(sk: paillier.PaillierPrivateKey, k: int) -> list:
    """k additive shares of e' = n^-1 mod lambda; any k-1 of them reveal nothing."""
    if k < 1:
        raise ValueError("need at least one trustee")
    n, lam = sk.public.n, sk.lam
    e_prime = modinv(n, lam)
    bound = n << SHARE_SLACK_BITS
    shares = [secrets.randbelow(bound) for _ in range(k - 1)]
    shares.append((e_prime - sum(shares)) % lam)
    return shares


def key_ceremony(paillier_bits: int, k: int):
    """Generate the election key, split it among k trustees, and drop the private key."""
    pk, sk = paillier.generate_keypair(paillier_bits)
    shares = split_key(sk, k)
    del sk   # the dealer keeps nothing; only the shares leave this function
    return pk, [Trustee(j, pk, s) for j, s in enumerate(shares)]


class Trustee:
    """Holds one additive share of the decryption exponent."""

    def __init__(self, index: int, public_key: PaillierPublicKey, share: int):
        self.index = index
        self.public_key = public_key
        self._share = share

    def partial_decrypt(self, encrypted_totals) -> list:
        """Partials for the published encrypted totals (hex), one per candidate."""
        n = self.public_key.n
        return [int_to_hex(pow(t % n, self._share, n)) for t in encrypted_totals]

    def export(self) -> dict:
        """The share as data, to hand to the trustee (e.g. as a file). Secret."""
        return {"trustee": self.index, "n": int_to_hex(self.public_key.n), "share": int_to_hex(self._share)}

    @classmethod
    def from_export(cls, d: dict) -> "Trustee":
        return cls(int(d["trustee"]), PaillierPublicKey(hex_to_int(d["n"])), hex_to_int(d["share"]))


# ------------------------------------------------------------------ combine + check
def combine(pk: PaillierPublicKey, total: int, partials) -> tuple:
    """Multiply the trustees' partials into R and read off m. Raises ValueError if they don't open `total`."""
    n = pk.n
    r = 1
    for p in partials:
        r = r * hex_to_int(p) % n
    if not is_unit(r, n, n):
        raise ValueError("combined randomness is not a unit mod n")
    u = total * modinv(pow(r, n, pk.n2), pk.n2) % pk.n2
    if (u - 1) % n:
        raise ValueError("partial decryptions do not open this total (a trustee share is wrong)")
    return (u - 1) // n, r


def check_opening(pk: PaillierPublicKey, total: int, m: int, r: int) -> bool:
    """Public check that `total` encrypts `m` with randomness `r`: g^m * r^n = total (mod n^2)."""
    if not isinstance(m, int) or not 0 <= m < pk.n or not is_unit(r, pk.n, pk.n) or not pk.is_valid_ciphertext(total):
        return False
    return pk.g_pow(m) * pow(r, pk.n, pk.n2) % pk.n2 == total


def build_results(pk: PaillierPublicKey, candidates, encrypted_totals, partials_by_trustee) -> list:
    """Result entries for the board. partials_by_trustee[j][i] = trustee j's partial for candidate i."""
    results = []
    for i, (name, t) in enumerate(zip(candidates, encrypted_totals)):
        partials = [p[i] for p in partials_by_trustee]
        m, r = combine(pk, t, partials)
        results.append({
            "candidate": i,
            "name": name,
            "encrypted_total": int_to_hex(t),
            "total": m,
            "randomness": int_to_hex(r),
            "partials": partials,
        })
    return results
