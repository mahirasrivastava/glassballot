"""Helpers to stand up a complete election in-process (demo, attacks, tests)."""

from .election.authority import ElectionAuthority
from .election.bulletin_board import BulletinBoard
from .election.service import ElectionService
from .election.tally import aggregate, key_ceremony
from .election.voter import Voter

DEFAULT_CANDIDATES = ("Alice", "Bob", "Carol")


def board_totals(entries) -> list:
    """What each trustee does before decrypting: recompute the encrypted totals from the board itself."""
    from .election.params import ElectionParams
    if not any(e["kind"] == "close" for e in entries):
        raise ValueError("polls are not closed")
    params = ElectionParams.from_dict(entries[0]["payload"])
    bodies = [e["payload"]["body"] for e in entries if e["kind"] == "ballot"]
    return aggregate(params.paillier_public_key, bodies, params.num_candidates)


class Election:
    """Authority, k trustees, service, board and registered voters, wired together."""

    def __init__(self, num_voters=5, candidates=DEFAULT_CANDIDATES, paillier_bits=2048,
                 authority_bits=2048, voter_bits=2048, board_path=None, title="Demo election",
                 board=None, trustees=3):
        self.board = board if board is not None else BulletinBoard(board_path)
        self.service = ElectionService(self.board)
        self.authority = ElectionAuthority(authority_bits)
        paillier_pk, self.trustees = key_ceremony(paillier_bits, trustees)
        self.params = self.service.create_election(title, candidates, self.authority.public_key,
                                                   paillier_pk, trustees)
        self.voters = []
        for i in range(num_voters):
            v = Voter(f"voter-{i + 1}", voter_bits)
            cred = self.authority.issue_credential(self.params.election_id, v.public_key)
            v.receive_credential(cred)
            self.service.register(cred)
            self.voters.append(v)

    def cast_all(self, choices):
        return [self.service.cast(v.cast(self.params, c)) for v, c in zip(self.voters, choices)]

    def partials(self) -> list:
        """Each trustee decrypts its share of the totals it recomputed from the public board."""
        totals = board_totals(self.board.entries())
        return [t.partial_decrypt(totals) for t in self.trustees]

    def finish(self):
        self.service.close()
        return self.service.publish_results(self.partials())
