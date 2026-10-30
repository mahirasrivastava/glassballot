"""The HTTP API end to end: a real server on a random port, voters built in Python (same format as the browser)."""

import json
import threading
import unittest
import urllib.error
import urllib.request

from tests.fixtures import TEST_RSA_BITS

from glassballot.crypto.encoding import int_to_hex
from glassballot.election.ballot import ballot_signing_bytes
from glassballot.election.params import ElectionParams
from glassballot.election.tally import Trustee
from glassballot.election.voter import Voter
from glassballot.simulation import board_totals
from glassballot.web import server as web


class Api:
    def __init__(self, base):
        self.base = base

    def call(self, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req) as res:
                return res.status, json.loads(res.read()), dict(res.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read()), dict(exc.headers)


class TestWebApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = web.AUTHORITY_BITS, web.MIN_VOTER_KEY_BITS
        web.AUTHORITY_BITS = web.MIN_VOTER_KEY_BITS = TEST_RSA_BITS   # small keys keep the test fast
        cls.server = web.make_server("127.0.0.1", 0, rate=0, workers=2)   # ballots checked in a process pool
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.api = Api(f"http://127.0.0.1:{cls.server.server_address[1]}")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.RequestHandlerClass.host.pool.shutdown()
        web.AUTHORITY_BITS, web.MIN_VOTER_KEY_BITS = cls.saved

    def register(self, code):
        v = Voter("v", TEST_RSA_BITS)
        status, res, _ = self.api.call("/api/register", {"code": code, "voter_public_key": v.public_key.to_dict()})
        self.assertEqual(status, 200, res)
        v.receive_credential(res["credential"])
        return v

    def test_full_election_over_http(self):
        api = self.api
        status, made, headers = api.call("/api/election", {"title": "API test", "candidates": ["A", "B"],
                                                          "voters": 3, "paillier_bits": 1024, "trustees": 2})
        self.assertEqual(status, 200, made)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        admin = {"X-Admin-Token": made["admin_token"]}
        codes = [c["code"] for c in made["codes"]]
        params = ElectionParams.from_dict(api.call("/api/board")[1][0]["payload"])
        self.assertEqual(params.trustees, 2)
        _, state, _ = api.call("/api/state")
        self.assertNotIn("admin_token", state)           # the handover is never repeated

        # registration: one-time codes, normalised input
        v1 = self.register(codes[0].lower().replace("-", " "))
        self.assertEqual(api.call("/api/register", {"code": codes[0], "voter_public_key": v1.public_key.to_dict()})[0], 409)
        self.assertEqual(api.call("/api/register", {"code": "AAAA-BBBB-CCCC", "voter_public_key": v1.public_key.to_dict()})[0], 403)
        v2 = self.register(codes[1])

        # voting
        status, res, _ = api.call("/api/vote", {"ballot": v1.cast(params, 1)})
        self.assertEqual(status, 200, res)
        self.assertEqual(api.call("/api/receipt", {"receipt": res["receipt"]})[1]["seq"], res["seq"])
        self.assertEqual(api.call("/api/vote", {"ballot": v1.cast(params, 0)})[0], 409)       # second ballot
        tampered = v2.cast(params, 0)
        tampered["body"]["ciphertexts"][0], tampered["body"]["ciphertexts"][1] = \
            tampered["body"]["ciphertexts"][1], tampered["body"]["ciphertexts"][0]
        tampered["signature"] = int_to_hex(v2._private_key.sign(ballot_signing_bytes(tampered["body"])))
        status, res, _ = api.call("/api/vote", {"ballot": tampered})
        self.assertEqual(status, 409)
        self.assertIn("proof", res["error"])
        self.assertEqual(api.call("/api/vote", {"ballot": v2.cast(params, 0)})[0], 200)

        # Benaloh audit of a spoiled ballot
        body, rs = self.spoiled_ballot(params, v2.credential["credential_id"], 1)
        self.assertTrue(api.call("/api/audit", {"body": body, "choice": 1, "randomness": rs})[1]["ok"])
        self.assertFalse(api.call("/api/audit", {"body": body, "choice": 0, "randomness": rs})[1]["ok"])

        # board is incremental
        all_entries = api.call("/api/board")[1]
        self.assertEqual(api.call("/api/board?since=3")[1], all_entries[3:])

        # only the authority closes; only real trustees decrypt
        self.assertEqual(api.call("/api/close", {})[0], 403)
        self.assertEqual(api.call("/api/admin/roll")[0], 403)
        roll = api.call("/api/admin/roll", headers=admin)[1]
        self.assertEqual([r["voted"] for r in roll], [True, True, False])
        self.assertEqual(api.call("/api/close", {}, admin)[0], 200)
        self.assertEqual(api.call("/api/vote", {"ballot": v2.cast(params, 1)})[0], 409)

        totals = board_totals(api.call("/api/board")[1])
        shares = made["trustee_shares"]
        t0 = Trustee.from_export(shares[0])
        wrong = {"trustee": 1, "token": shares[0]["token"], "partials": t0.partial_decrypt(totals)}
        self.assertEqual(api.call("/api/trustee/partial", wrong)[0], 403)
        res = api.call("/api/trustee/partial", {"trustee": 0, "token": shares[0]["token"],
                                                "partials": t0.partial_decrypt(totals)})[1]
        self.assertFalse(res["published"])
        self.assertEqual(api.call("/api/verify")[0], 409)
        t1 = Trustee.from_export(shares[1])
        res = api.call("/api/trustee/partial", {"trustee": 1, "token": shares[1]["token"],
                                                "partials": t1.partial_decrypt(totals)})[1]
        self.assertTrue(res["published"])
        self.assertEqual(res["results"], [{"name": "A", "total": 1}, {"name": "B", "total": 1}])
        report = api.call("/api/verify")[1]
        self.assertTrue(report["ok"], report)

    def spoiled_ballot(self, params, credential_id, choice):
        """What the browser keeps for a Benaloh audit: ciphertexts plus the randomness behind them."""
        pk = params.paillier_public_key
        opened = [pk.encrypt(1 if i == choice else 0) for i in range(params.num_candidates)]
        body = {"election_id": params.election_id, "credential_id": credential_id,
                "ciphertexts": [int_to_hex(c) for c, _ in opened]}
        return body, [int_to_hex(r) for _, r in opened]

    def test_proxy_mode_limits_each_forwarded_client(self):
        srv = web.make_server("127.0.0.1", 0, rate=0.01, burst=1, proxy=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        api = Api(f"http://127.0.0.1:{srv.server_address[1]}")
        try:
            post = lambda ip: api.call("/api/receipt", {"receipt": "x"}, {"X-Forwarded-For": f"{ip}, 10.0.0.1"})[0]
            self.assertEqual([post("1.1.1.1"), post("1.1.1.1"), post("2.2.2.2")], [409, 429, 409])
            headers = api.call("/api/state", headers={"X-Forwarded-Proto": "https"})[2]
            self.assertIn("Strict-Transport-Security", headers)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_rate_limit(self):
        limiter = web.RateLimiter(rate=1, burst=2)
        self.assertEqual([limiter.allow("ip") for _ in range(3)], [True, True, False])
        self.assertTrue(limiter.allow("other-ip"))


if __name__ == "__main__":
    unittest.main()
