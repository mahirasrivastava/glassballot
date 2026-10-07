import copy
import tempfile
import unittest
from pathlib import Path

from tests.fixtures import small_election

from glassballot.crypto.encoding import int_to_hex
from glassballot.election.ballot import ballot_signing_bytes
from glassballot.election.bulletin_board import BulletinBoard, load_entries, verify_chain
from glassballot.election.service import Rejected
from glassballot.election.tally import aggregate
from glassballot.election.verifier import verify_election


def failed_checks(entries):
    return {c.name for c in verify_election(entries).checks if not c.ok}


class TestBulletinBoard(unittest.TestCase):
    def test_chain_and_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "b.jsonl"
            board = BulletinBoard(path)
            for i in range(3):
                board.append("credential", {"i": i})
            entries = load_entries(path)
            self.assertTrue(verify_chain(entries)[0])
            self.assertEqual(len(BulletinBoard(path)), 3)   # reload re-checks the chain

    def test_tamper_reorder_delete_detected(self):
        board = BulletinBoard()
        for i in range(3):
            board.append("credential", {"i": i})
        e = board.entries()
        edited = copy.deepcopy(e); edited[1]["payload"]["i"] = 9
        deleted = e[:1] + e[2:]
        swapped = [e[1], e[0], e[2]]
        for bad in (edited, deleted, swapped):
            self.assertFalse(verify_chain(bad)[0])

    def test_entries_are_copies(self):
        board = BulletinBoard()
        board.append("credential", {"i": 1})
        board.entries()[0]["payload"]["i"] = 2
        self.assertEqual(board.entries()[0]["payload"]["i"], 1)


class TestHonestElection(unittest.TestCase):
    def test_end_to_end(self):
        el = small_election(5)
        el.cast_all([0, 2, 2, 1, 2])
        results = el.finish()
        self.assertEqual([r["total"] for r in results], [1, 1, 3])
        rep = verify_election(el.board.entries())
        self.assertTrue(rep.ok, rep.render())

    def test_abstentions_allowed(self):
        el = small_election(3)
        el.cast_all([1])                       # only one of three voters casts
        el.finish()
        self.assertTrue(verify_election(el.board.entries()).ok)


class TestServiceRejects(unittest.TestCase):
    def setUp(self):
        self.el = small_election(3)

    def test_double_vote(self):
        v = self.el.voters[0]
        self.el.service.cast(v.cast(self.el.params, 0))
        with self.assertRaises(Rejected):
            self.el.service.cast(v.cast(self.el.params, 1))

    def test_unregistered_voter(self):
        from glassballot.election.voter import Voter
        stranger = Voter("x", 768)
        stranger.receive_credential(self.el.voters[0].credential | {"credential_id": stranger.public_key.fingerprint()})
        with self.assertRaises(Rejected):
            self.el.service.cast(stranger.cast(self.el.params, 0))

    def test_forged_credential(self):
        from glassballot.election.authority import ElectionAuthority
        from glassballot.election.voter import Voter
        rogue = ElectionAuthority(768)
        v = Voter("x", 768)
        with self.assertRaises(Rejected):
            self.el.service.register(rogue.issue_credential(self.el.params.election_id, v.public_key))

    def test_replayed_ballot_under_other_credential(self):
        a, b = self.el.voters[0], self.el.voters[1]
        body = copy.deepcopy(a.cast(self.el.params, 0)["body"])
        body["credential_id"] = b.credential["credential_id"]
        signed = {"body": body, "signature": int_to_hex(b._private_key.sign(ballot_signing_bytes(body)))}
        with self.assertRaisesRegex(Rejected, "proof"):
            self.el.service.cast(signed)

    def test_vote_for_two_candidates(self):
        """Two ciphertexts of 1: each 0-or-1 proof passes, the sum proof must fail."""
        v, pk = self.el.voters[0], self.el.params.paillier_public_key
        a = v.cast(self.el.params, 0)["body"]
        b = v.cast(self.el.params, 1)["body"]
        body = copy.deepcopy(a)
        body["ciphertexts"][1] = b["ciphertexts"][1]
        body["choice_proofs"][1] = b["choice_proofs"][1]
        signed = {"body": body, "signature": int_to_hex(v._private_key.sign(ballot_signing_bytes(body)))}
        with self.assertRaisesRegex(Rejected, "sum-equals-1"):
            self.el.service.cast(signed)

    def test_cast_after_close(self):
        self.el.service.close()
        with self.assertRaises(Rejected):
            self.el.service.cast(self.el.voters[0].cast(self.el.params, 0))


class TestVerifierCatchesDishonestServer(unittest.TestCase):
    def test_dropped_ballot(self):
        el = small_election(3)
        el.cast_all([0, 0, 1])
        el.service.close()
        p = el.params
        bodies = [e["payload"]["body"] for e in el.board.entries("ballot")][1:]
        res = el.trustee.decrypt_tally(p.election_id, p.candidates, aggregate(p.paillier_public_key, bodies, 3))
        el.board.append("result", {"election_id": p.election_id, "results": res})
        self.assertIn("homomorphic tally", failed_checks(el.board.entries()))

    def test_wrong_total(self):
        el = small_election(3)
        el.cast_all([0, 1, 1])
        el.finish()
        entries = el.board.entries()
        entries[-1]["payload"]["results"][0]["total"] += 1
        # Re-hash the tampered entry so only the cryptographic check can catch it.
        from glassballot.election.bulletin_board import compute_entry_hash
        last = entries[-1]
        last["entry_hash"] = compute_entry_hash(last["seq"], last["kind"], last["payload"], last["prev_hash"])
        self.assertIn("decryption proofs", failed_checks(entries))

    def test_edited_row(self):
        el = small_election(2)
        el.cast_all([0, 1])
        el.finish()
        entries = el.board.entries()
        entries[3]["payload"]["signature"] = "1"
        self.assertEqual(failed_checks(entries), {"hash chain"})


if __name__ == "__main__":
    unittest.main()
