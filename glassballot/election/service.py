"""Election service: accepts or rejects requests and writes accepted ones to the board.

It is NOT trusted: the verifier re-checks everything it published.

Casting is split in three so a web server can verify ballots in parallel:
    precheck(signed)          cheap: well-formed, registered, not yet voted, polls open
    check_ballot(...)         expensive, pure: signature + every ZK proof (runs in any process)
    commit(signed)            under the caller's lock: re-check, then append to the board
cast() runs all three in order.
"""

import secrets

from ..crypto.encoding import hex_to_int
from ..crypto.rsa import RSAPublicKey
from .authority import verify_credential
from .ballot import InvalidBallot, ballot_hash, ballot_signing_bytes, verify_ballot_body
from .bulletin_board import BulletinBoard
from .params import ElectionParams
from .tally import aggregate, build_results


class Rejected(Exception):
    """A request the service refused; message says why."""


def check_ballot(params: dict, voter_public_key: dict, signed_ballot: dict) -> None:
    """Voter signature and all ballot proofs. Pure (plain dicts in) so it can run in a worker process."""
    p = ElectionParams.from_dict(params)
    body = signed_ballot["body"]
    try:
        signature = hex_to_int(signed_ballot["signature"])
    except (KeyError, TypeError, ValueError):
        raise Rejected("malformed signature")
    if not RSAPublicKey.from_dict(voter_public_key).verify(ballot_signing_bytes(body), signature):
        raise Rejected("ballot signature invalid")
    try:
        verify_ballot_body(p.paillier_public_key, p.election_id, p.num_candidates, body)
    except InvalidBallot as exc:
        raise Rejected(f"ballot proof rejected: {exc}")


class ElectionService:
    def __init__(self, board: BulletinBoard):
        self.board = board
        self.params = None
        self._credentials = {}   # credential_id -> credential
        self._voted = set()      # credential_ids that already cast
        self._receipts = {}      # receipt -> board seq
        self._closed = False

    # ---------------------------------------------------------------- setup
    def create_election(self, title, candidates, authority_public_key, paillier_public_key,
                        trustees: int = 1) -> ElectionParams:
        if self.params is not None:
            raise Rejected("election already created")
        if len(candidates) < 2:
            raise Rejected("need at least two candidates")
        self.params = ElectionParams(secrets.token_hex(8), title, tuple(candidates),
                                     paillier_public_key, authority_public_key, trustees)
        self.board.append("election", self.params.to_dict())
        return self.params

    # --------------------------------------------------------- registration
    def register(self, credential: dict) -> dict:
        self._require_open()
        if not verify_credential(self.params.authority_public_key, credential, self.params.election_id):
            raise Rejected("credential signature invalid")
        if credential["credential_id"] in self._credentials:
            raise Rejected("credential already registered")
        self._credentials[credential["credential_id"]] = credential
        return self.board.append("credential", credential)

    # -------------------------------------------------------------- casting
    def precheck(self, signed_ballot: dict) -> dict:
        """Cheap checks; returns the voter's public key (dict) for check_ballot."""
        self._require_open()
        try:
            body = signed_ballot["body"]
            cred_id = body["credential_id"]
            hash(cred_id)
        except (KeyError, TypeError):
            raise Rejected("malformed ballot")
        credential = self._credentials.get(cred_id)
        if credential is None:
            raise Rejected("credential not on the voter roll")
        if cred_id in self._voted:
            raise Rejected("this credential has already voted")
        return credential["voter_public_key"]

    def commit(self, signed_ballot: dict) -> dict:
        """Append an already-verified ballot. Call under the same lock as other writes."""
        self.precheck(signed_ballot)   # state may have changed while it was being verified
        self._voted.add(signed_ballot["body"]["credential_id"])
        entry = self.board.append("ballot", signed_ballot)
        receipt = ballot_hash(signed_ballot)
        self._receipts[receipt] = entry["seq"]
        return {"receipt": receipt, "seq": entry["seq"], "board_head": entry["entry_hash"]}

    def cast(self, signed_ballot: dict) -> str:
        """Validate and post a ballot; return the receipt hash."""
        voter_key = self.precheck(signed_ballot)
        check_ballot(self.params.to_dict(), voter_key, signed_ballot)
        return self.commit(signed_ballot)["receipt"]

    def find_receipt(self, receipt: str):
        return self._receipts.get(receipt)

    def has_voted(self, credential_id: str) -> bool:
        return credential_id in self._voted

    @property
    def ballot_count(self) -> int:
        return len(self._voted)

    @property
    def closed(self) -> bool:
        return self._closed

    # ---------------------------------------------------- close and tally
    def close(self) -> None:
        self._require_open()
        self._closed = True
        self.board.append("close", {"election_id": self.params.election_id,
                                    "ballot_count": len(self._voted),
                                    "board_head": self.board.head})

    def encrypted_totals(self) -> list:
        if not self._closed:
            raise Rejected("close the election before tallying")
        bodies = [e["payload"]["body"] for e in self.board.entries("ballot")]
        return aggregate(self.params.paillier_public_key, bodies, self.params.num_candidates)

    def publish_results(self, partials_by_trustee) -> list:
        """Combine one list of partial decryptions per trustee, check the opening, post the result."""
        p = self.params
        totals = self.encrypted_totals()
        if self.board.entries("result"):
            raise Rejected("results already published")
        if len(partials_by_trustee) != p.trustees or any(
                not isinstance(x, list) or len(x) != p.num_candidates for x in partials_by_trustee):
            raise Rejected(f"need one partial per candidate from each of the {p.trustees} trustees")
        try:
            results = build_results(p.paillier_public_key, p.candidates, totals, partials_by_trustee)
        except (TypeError, ValueError) as exc:
            raise Rejected(f"partial decryptions rejected: {exc}")
        self.board.append("result", {"election_id": p.election_id, "results": results})
        return results

    def _require_open(self):
        if self.params is None:
            raise Rejected("no election")
        if self._closed:
            raise Rejected("election is closed")
