"""M1 - Voter registration & eligibility.

Each voter generates their own RSA keypair. The election authority signs a
credential binding (election_id, voter public key). The credential is public
(it goes on the voter roll); only the holder of the matching private key can
sign a ballot under it, so publishing the roll leaks nothing usable.

credential_id = SHA-256 fingerprint of the voter's public key.
"""

from ..crypto import rsa
from ..crypto.encoding import canonical_json, hex_to_int, int_to_hex
from ..crypto.rsa import RSAPublicKey

CREDENTIAL_FIELDS = ("election_id", "credential_id", "voter_public_key")


def credential_payload(credential: dict) -> dict:
    """The signed part of a credential (everything except the signature)."""
    return {k: credential[k] for k in CREDENTIAL_FIELDS}


class ElectionAuthority:
    def __init__(self, rsa_bits: int = 2048):
        self.public_key, self._private_key = rsa.generate_keypair(rsa_bits)

    def issue_credential(self, election_id: str, voter_public_key: RSAPublicKey) -> dict:
        payload = {
            "election_id": election_id,
            "credential_id": voter_public_key.fingerprint(),
            "voter_public_key": voter_public_key.to_dict(),
        }
        signature = self._private_key.sign(canonical_json(payload))
        return {**payload, "signature": int_to_hex(signature)}


def verify_credential(authority_public_key: RSAPublicKey, credential: dict, election_id: str) -> bool:
    try:
        payload = credential_payload(credential)
        signature = hex_to_int(credential["signature"])
        voter_key = RSAPublicKey.from_dict(payload["voter_public_key"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        payload["election_id"] == election_id
        and payload["credential_id"] == voter_key.fingerprint()
        and authority_public_key.verify(canonical_json(payload), signature)
    )
