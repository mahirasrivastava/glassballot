import unittest

from tests.fixtures import paillier_keys, rsa_keys

from glassballot.crypto import numtheory
from glassballot.crypto.encoding import canonical_json, hex_to_int, int_to_hex
from glassballot.crypto.proofs import prove_decryption, prove_sum, verify_decryption, verify_sum
from glassballot.crypto.sigma import prove_binary, verify_binary


class TestNumberTheory(unittest.TestCase):
    def test_primality(self):
        self.assertTrue(all(numtheory.is_probable_prime(p) for p in (2, 3, 7919, 2**127 - 1)))
        # 561 is a Carmichael number; 2**127+1 is divisible by 3.
        self.assertFalse(any(numtheory.is_probable_prime(c) for c in (0, 1, 561, 2**127 + 1)))

    def test_random_prime_size(self):
        p = numtheory.random_prime(128)
        self.assertEqual(p.bit_length(), 128)
        self.assertTrue(numtheory.is_probable_prime(p))


class TestEncoding(unittest.TestCase):
    def test_hex_round_trip_and_rejects(self):
        self.assertEqual(hex_to_int(int_to_hex(2**300 + 5)), 2**300 + 5)
        for bad in ("", "0x1f", "1F", "zz", 5):
            with self.assertRaises(ValueError):
                hex_to_int(bad)

    def test_canonical_json_is_order_independent(self):
        self.assertEqual(canonical_json({"b": 1, "a": [2]}), canonical_json({"a": [2], "b": 1}))


class TestPaillier(unittest.TestCase):
    def setUp(self):
        self.pk, self.sk = paillier_keys()

    def test_encrypt_decrypt(self):
        for m in (0, 1, 42, self.pk.n - 1):
            c, _ = self.pk.encrypt(m)
            self.assertEqual(self.sk.decrypt(c), m)

    def test_additive_homomorphism(self):
        cs = [self.pk.encrypt(m)[0] for m in (3, 0, 1, 7)]
        self.assertEqual(self.sk.decrypt(self.pk.sum(cs)), 11)

    def test_probabilistic(self):
        self.assertNotEqual(self.pk.encrypt(1)[0], self.pk.encrypt(1)[0])

    def test_recover_randomness(self):
        c, r = self.pk.encrypt(5)
        self.assertEqual(self.sk.recover_randomness(c, 5), r)
        with self.assertRaises(ValueError):
            self.sk.recover_randomness(c, 6)

    def test_g_pow_matches_definition(self):
        for m in (0, 1, 2, -1, -3):
            self.assertEqual(self.pk.g_pow(m), pow(self.pk.g, m, self.pk.n2))

    def test_range_check(self):
        with self.assertRaises(ValueError):
            self.pk.encrypt(self.pk.n)


class TestRSA(unittest.TestCase):
    def test_sign_verify(self):
        pub, priv = rsa_keys()
        s = priv.sign(b"ballot")
        self.assertTrue(pub.verify(b"ballot", s))
        self.assertFalse(pub.verify(b"ballot!", s))
        self.assertFalse(pub.verify(b"ballot", s ^ 1))
        self.assertFalse(pub.verify(b"ballot", pub.n + 1))


class TestBinaryProof(unittest.TestCase):
    def setUp(self):
        self.pk, _ = paillier_keys()
        self.ctx = {"election_id": "e", "credential_id": "v", "candidate": 0}

    def test_completeness_for_0_and_1(self):
        for m in (0, 1):
            c, r = self.pk.encrypt(m)
            self.assertTrue(verify_binary(self.pk, c, prove_binary(self.pk, c, m, r, self.ctx), self.ctx))

    def test_prover_refuses_non_binary(self):
        c, r = self.pk.encrypt(2)
        with self.assertRaises(ValueError):
            prove_binary(self.pk, c, 2, r, self.ctx)

    def test_soundness_proof_not_transferable_to_other_ciphertext(self):
        c1, r1 = self.pk.encrypt(1)
        proof = prove_binary(self.pk, c1, 1, r1, self.ctx)
        c2, _ = self.pk.encrypt(2)
        self.assertFalse(verify_binary(self.pk, c2, proof, self.ctx))

    def test_context_binding(self):
        c, r = self.pk.encrypt(0)
        proof = prove_binary(self.pk, c, 0, r, self.ctx)
        self.assertFalse(verify_binary(self.pk, c, proof, {**self.ctx, "credential_id": "other"}))

    def test_tampered_proof_fields(self):
        c, r = self.pk.encrypt(1)
        proof = prove_binary(self.pk, c, 1, r, self.ctx)
        for key in proof:
            bad = dict(proof)
            bad[key] = int_to_hex(hex_to_int(bad[key]) + 1)
            self.assertFalse(verify_binary(self.pk, c, bad, self.ctx), key)
        self.assertFalse(verify_binary(self.pk, c, {"a0": "1"}, self.ctx))


class TestSumAndDecryptionProofs(unittest.TestCase):
    def setUp(self):
        self.pk, self.sk = paillier_keys()
        self.ctx = {"election_id": "e"}

    def test_sum_proof(self):
        enc = [self.pk.encrypt(m) for m in (0, 1, 0)]
        cs, r = [c for c, _ in enc], 1
        for _, ri in enc:
            r = r * ri % self.pk.n
        proof = prove_sum(self.pk, cs, 1, r, self.ctx)
        self.assertTrue(verify_sum(self.pk, cs, 1, proof, self.ctx))
        self.assertFalse(verify_sum(self.pk, cs, 2, proof, self.ctx))

    def test_decryption_proof(self):
        c = self.pk.sum(self.pk.encrypt(m)[0] for m in (1, 1, 0, 1))
        proof = prove_decryption(self.sk, c, 3, self.ctx)
        self.assertTrue(verify_decryption(self.pk, c, 3, proof, self.ctx))
        self.assertFalse(verify_decryption(self.pk, c, 4, proof, self.ctx))
        self.assertFalse(verify_decryption(self.pk, c, 3, proof, {"election_id": "other"}))

    def test_trustee_cannot_prove_wrong_result(self):
        c, _ = self.pk.encrypt(3)
        with self.assertRaises(ValueError):
            prove_decryption(self.sk, c, 4, self.ctx)


if __name__ == "__main__":
    unittest.main()
