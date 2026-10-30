"""The browser's crypto (gbcrypto.js, run under Node) must be byte-compatible with the Python side.

Skipped when `node` is not installed; everything else in the suite stays stdlib-only.
"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from tests.fixtures import TEST_PAILLIER_BITS, TEST_RSA_BITS, paillier_keys, small_election

from glassballot.crypto.encoding import canonical_json, hash_obj, hex_to_int, int_to_hex
from glassballot.crypto.fiat_shamir import DOMAIN_BINARY, challenge
from glassballot.crypto.rsa import RSAPublicKey
from glassballot.election.ballot import ballot_hash, verify_ballot_body
from glassballot.election.tally import Trustee, aggregate, split_key

HARNESS = Path(__file__).resolve().parent / "js" / "harness.js"
NODE = shutil.which("node")


def js(op, **args):
    out = subprocess.run([NODE, str(HARNESS)], input=json.dumps({"op": op, **args}),
                         capture_output=True, text=True, timeout=300, check=True)
    return json.loads(out.stdout)


@unittest.skipUnless(NODE, "node not installed")
class TestJsMatchesPython(unittest.TestCase):
    def test_canonical_json_and_sha256(self):
        objects = [
            {"b": 1, "a": [2, {"z": None, "y": True}], "c": "x"},
            {"title": "Élection — 2026   ✓ 日本", "ctl": "tab\there\nnew\x01\x1f\"q\"\\", "e": ""},
            [], {}, [0, -5, 12345678901234],
        ]
        for o, got in zip(objects, js("hash", objects=objects)):
            self.assertEqual(got["canonical"].encode("utf-8"), canonical_json(o))
            self.assertEqual(got["sha256"], hash_obj(o))

    def test_fiat_shamir_challenge(self):
        t = {"n": "abc", "context": {"election_id": "e", "candidate": 2}, "c": "ff"}
        self.assertEqual(hex_to_int(js("challenge", domain=DOMAIN_BINARY, transcript=t)), challenge(DOMAIN_BINARY, t))

    def test_rsa_signature_verifies_in_python(self):
        got = js("rsa", bits=1024, message="glass ballot")
        pub = RSAPublicKey.from_dict(got["public_key"])
        self.assertEqual(pub.n.bit_length(), 1024)
        self.assertEqual(got["fingerprint"], pub.fingerprint())
        self.assertTrue(pub.verify(b"glass ballot", hex_to_int(got["signature"])))
        self.assertFalse(pub.verify(b"glass ballot!", hex_to_int(got["signature"])))

    def test_browser_ballot_accepted_by_service_and_verifier(self):
        el = small_election(0, ("A", "B", "C"))
        p = el.params
        got = js("ballot", n=int_to_hex(p.paillier_public_key.n), election_id=p.election_id,
                 num_candidates=3, choice=1, bits=TEST_RSA_BITS)
        verify_ballot_body(p.paillier_public_key, p.election_id, 3, got["signed"]["body"])
        cred = el.authority.issue_credential(p.election_id, RSAPublicKey.from_dict(got["public_key"]))
        el.service.register(cred)
        self.assertEqual(el.service.cast(got["signed"]), got["receipt"])
        self.assertEqual(ballot_hash(got["signed"]), got["receipt"])
        self.assertEqual(got["audit_true"], [True, True, True])
        self.assertEqual(got["audit_wrong"], [True, False, False])   # candidate 0 still holds 0, the rest no longer open
        results = el.finish()
        self.assertEqual([r["total"] for r in results], [0, 1, 0])

    def test_trustee_partials_and_aggregate_match(self):
        pk, sk = paillier_keys()
        trustees = [Trustee(j, pk, s) for j, s in enumerate(split_key(sk, 3))]
        bodies = [{"ciphertexts": [int_to_hex(pk.encrypt(m)[0]) for m in (1, 0)]} for _ in range(4)]
        totals = aggregate(pk, bodies, 2)
        n = int_to_hex(pk.n)
        self.assertEqual(js("aggregate", n=n, bodies=bodies, k=2), [int_to_hex(t) for t in totals])
        for t in trustees:
            share = t.export()["share"]
            self.assertEqual(js("partial", n=n, share=share, totals=[int_to_hex(x) for x in totals]),
                             t.partial_decrypt(totals))


if __name__ == "__main__":
    unittest.main()
