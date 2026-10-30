import unittest

from tests.fixtures import paillier_keys, small_election

from glassballot.crypto.encoding import hex_to_int, int_to_hex
from glassballot.election.service import Rejected
from glassballot.election.tally import Trustee, check_opening, combine, split_key
from glassballot.election.verifier import verify_election


def trustees_for(k):
    pk, sk = paillier_keys()
    return pk, [Trustee(j, pk, s) for j, s in enumerate(split_key(sk, k))]


class TestThresholdDecryption(unittest.TestCase):
    def test_all_trustees_open_a_sum(self):
        for k in (1, 2, 3, 5):
            pk, trustees = trustees_for(k)
            total = pk.sum(pk.encrypt(m)[0] for m in (1, 0, 1, 1))
            m, r = combine(pk, total, [t.partial_decrypt([total])[0] for t in trustees])
            self.assertEqual(m, 3)
            self.assertTrue(check_opening(pk, total, m, r))

    def test_missing_trustee_cannot_open(self):
        pk, trustees = trustees_for(3)
        c, _ = pk.encrypt(1)
        partials = [t.partial_decrypt([c])[0] for t in trustees[:2]]
        with self.assertRaises(ValueError):
            combine(pk, c, partials)

    def test_single_share_reveals_nothing_usable(self):
        """One trustee's partial on a single ballot is not that ballot's randomness."""
        pk, trustees = trustees_for(3)
        c, r = pk.encrypt(1)
        self.assertNotEqual(hex_to_int(trustees[0].partial_decrypt([c])[0]), r)

    def test_bad_partial_rejected(self):
        pk, trustees = trustees_for(3)
        c, _ = pk.encrypt(1)
        partials = [t.partial_decrypt([c])[0] for t in trustees]
        partials[1] = int_to_hex(hex_to_int(partials[1]) * 2 % pk.n)
        with self.assertRaises(ValueError):
            combine(pk, c, partials)

    def test_opening_rejects_wrong_total(self):
        pk, trustees = trustees_for(2)
        c, _ = pk.encrypt(5)
        m, r = combine(pk, c, [t.partial_decrypt([c])[0] for t in trustees])
        self.assertFalse(check_opening(pk, c, m + 1, r))

    def test_share_export_round_trip(self):
        pk, trustees = trustees_for(2)
        again = [Trustee.from_export(t.export()) for t in trustees]
        c, _ = pk.encrypt(1)
        self.assertEqual([t.partial_decrypt([c]) for t in again], [t.partial_decrypt([c]) for t in trustees])


class TestThresholdElection(unittest.TestCase):
    def test_service_rejects_short_or_bad_partials(self):
        el = small_election(2)
        el.cast_all([0, 1])
        el.service.close()
        partials = el.partials()
        with self.assertRaises(Rejected):
            el.service.publish_results(partials[:-1])
        bad = [list(p) for p in partials]
        bad[0][0] = "2"
        with self.assertRaises(Rejected):
            el.service.publish_results(bad)
        el.service.publish_results(partials)
        self.assertTrue(verify_election(el.board.entries()).ok)

    def test_verifier_catches_forged_partial_product(self):
        el = small_election(2)
        el.cast_all([0, 1])
        el.finish()
        entries = el.board.entries()
        r = entries[-1]["payload"]["results"][0]
        r["partials"][0] = int_to_hex(hex_to_int(r["partials"][0]) + 1)
        from glassballot.election.bulletin_board import compute_entry_hash
        last = entries[-1]
        last["entry_hash"] = compute_entry_hash(last["seq"], last["kind"], last["payload"], last["prev_hash"])
        rep = verify_election(entries)
        self.assertIn("decryption proofs", {c.name for c in rep.checks if not c.ok})


if __name__ == "__main__":
    unittest.main()
