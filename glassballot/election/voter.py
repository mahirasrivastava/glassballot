"""M2 - The voter's side: own RSA keys, credential, encrypt + prove + sign."""

from ..crypto import rsa
from ..crypto.encoding import int_to_hex
from .ballot import ballot_hash, ballot_signing_bytes, encrypt_ballot
from .params import ElectionParams


class Voter:
    def __init__(self, name: str, rsa_bits: int = 2048):
        self.name = name
        self.public_key, self._private_key = rsa.generate_keypair(rsa_bits)
        self.credential = None
        self.receipt = None

    def receive_credential(self, credential: dict) -> None:
        if credential["credential_id"] != self.public_key.fingerprint():
            raise ValueError("credential was issued for a different key")
        self.credential = credential

    def cast(self, params: ElectionParams, choice: int) -> dict:
        if self.credential is None:
            raise RuntimeError("voter has no credential")
        body = encrypt_ballot(params.paillier_public_key, params.election_id,
                              self.credential["credential_id"], params.num_candidates, choice)
        signed = {"body": body, "signature": int_to_hex(self._private_key.sign(ballot_signing_bytes(body)))}
        self.receipt = ballot_hash(signed)
        return signed
