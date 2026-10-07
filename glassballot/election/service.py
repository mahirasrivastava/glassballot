"""Election service: the logic a Flask API will wrap later.

It accepts or rejects requests and writes accepted ones to the bulletin
board. It is NOT trusted: the verifier re-checks everything it published.
"""

import secrets

from ..crypto.encoding import hex_to_int
from ..crypto.rsa import RSAPublicKey
from .authority import verify_credential
from .ballot import InvalidBallot, ballot_hash, ballot_signing_bytes, verify_ballot_body
from .bulletin_board import BulletinBoard
from .params import ElectionParams
from .tally import Trustee, aggregate


class Rejected(Exception):
    """A request the service refused; message says why."""


class ElectionService:
    def __init__(self, board: BulletinBoard):
        self.board = board
        self.params = None
        self._credentials = {}   # credential_id -> credential
        self._voted = set()      # credential_ids that already cast
        self._closed = False

    # ---------------------------------------------------------------- setup
    def create_election(self, title, candidates, authority_public_key, paillier_public_key) -> ElectionParams:
        if self.params is not None:
            raise Rejected("election already created")
        if len(candidates) < 2:
            raise Rejected("need at least two candidates")
        self.params = ElectionParams(secrets.token_hex(8), title, tuple(candidates),
                                     paillier_public_key, authority_public_key)
        self.board.append("election", self.params.to_dict())
        return self.params

    # --------------------------------------------------------- registration
    def register(self, credential: dict) -> None:
        self._require_open()
        if not verify_credential(self.params.authority_public_key, credential, self.params.election_id):
            raise Rejected("credential signature invalid")
        if credential["credential_id"] in self._credentials:
            raise Rejected("credential already registered")
        self._credentials[credential["credential_id"]] = credential
        self.board.append("credential", credential)

    # -------------------------------------------------------------- casting
    def cast(self, signed_ballot: dict) -> str:
        """Validate and post a ballot; return the receipt hash."""
        self._require_open()
        try:
            body, signature = signed_ballot["body"], hex_to_int(signed_ballot["signature"])
            cred_id = body["credential_id"]
        except (KeyError, TypeError, ValueError):
            raise Rejected("malformed ballot")
        credential = self._credentials.get(cred_id)
        if credential is None:
            raise Rejected("credential not on the voter roll")
        if cred_id in self._voted:
            raise Rejected("this credential has already voted")
        voter_key = RSAPublicKey.from_dict(credential["voter_public_key"])
        if not voter_key.verify(ballot_signing_bytes(body), signature):
            raise Rejected("ballot signature invalid")
        p = self.params
        try:
            verify_ballot_body(p.paillier_public_key, p.election_id, p.num_candidates, body)
        except InvalidBallot as exc:
            raise Rejected(f"ballot proof rejected: {exc}")
        self._voted.add(cred_id)
        self.board.append("ballot", signed_ballot)
        return ballot_hash(signed_ballot)

    # ---------------------------------------------------- close and tally
    def close(self) -> None:
        self._require_open()
        self._closed = True
        self.board.append("close", {"election_id": self.params.election_id,
                                    "ballot_count": len(self._voted),
                                    "board_head": self.board.head})

    def publish_results(self, trustee: Trustee) -> list:
        if not self._closed:
            raise Rejected("close the election before tallying")
        p = self.params
        bodies = [e["payload"]["body"] for e in self.board.entries("ballot")]
        totals = aggregate(p.paillier_public_key, bodies, p.num_candidates)
        results = trustee.decrypt_tally(p.election_id, p.candidates, totals)
        self.board.append("result", {"election_id": p.election_id, "results": results})
        return results

    def _require_open(self):
        if self.params is None:
            raise Rejected("no election created")
        if self._closed:
            raise Rejected("election is closed")
