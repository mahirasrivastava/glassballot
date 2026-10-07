"""Public election parameters, posted as the first bulletin-board entry."""

from dataclasses import dataclass

from ..crypto.paillier import PaillierPublicKey
from ..crypto.rsa import RSAPublicKey


@dataclass(frozen=True)
class ElectionParams:
    election_id: str
    title: str
    candidates: tuple
    paillier_public_key: PaillierPublicKey
    authority_public_key: RSAPublicKey

    @property
    def num_candidates(self) -> int:
        return len(self.candidates)

    def to_dict(self) -> dict:
        return {
            "election_id": self.election_id,
            "title": self.title,
            "candidates": list(self.candidates),
            "paillier_public_key": self.paillier_public_key.to_dict(),
            "authority_public_key": self.authority_public_key.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ElectionParams":
        return cls(
            election_id=d["election_id"],
            title=d["title"],
            candidates=tuple(d["candidates"]),
            paillier_public_key=PaillierPublicKey.from_dict(d["paillier_public_key"]),
            authority_public_key=RSAPublicKey.from_dict(d["authority_public_key"]),
        )
