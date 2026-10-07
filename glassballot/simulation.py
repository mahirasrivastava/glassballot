"""Helpers to stand up a complete election in-process (demo, attacks, tests)."""

from .election.authority import ElectionAuthority
from .election.bulletin_board import BulletinBoard
from .election.service import ElectionService
from .election.tally import Trustee
from .election.voter import Voter

DEFAULT_CANDIDATES = ("Alice", "Bob", "Carol")


class Election:
    """Authority, trustee, service, board and registered voters, wired together."""

    def __init__(self, num_voters=5, candidates=DEFAULT_CANDIDATES, paillier_bits=2048,
                 authority_bits=2048, voter_bits=1024, board_path=None, title="Demo election"):
        self.board = BulletinBoard(board_path)
        self.service = ElectionService(self.board)
        self.authority = ElectionAuthority(authority_bits)
        self.trustee = Trustee(paillier_bits)
        self.params = self.service.create_election(title, candidates,
                                                   self.authority.public_key, self.trustee.public_key)
        self.voters = []
        for i in range(num_voters):
            v = Voter(f"voter-{i + 1}", voter_bits)
            cred = self.authority.issue_credential(self.params.election_id, v.public_key)
            v.receive_credential(cred)
            self.service.register(cred)
            self.voters.append(v)

    def cast_all(self, choices):
        return [self.service.cast(v.cast(self.params, c)) for v, c in zip(self.voters, choices)]

    def finish(self):
        self.service.close()
        return self.service.publish_results(self.trustee)
