#!/usr/bin/env python3
"""Runs each attack from the plan's attack table and shows where it is caught.

    python scripts/attack_demo.py            # fast, 1024-bit demo keys
    python scripts/attack_demo.py --bits 2048
"""

import argparse
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from glassballot.crypto.encoding import int_to_hex                   # noqa: E402
from glassballot.election.ballot import ballot_signing_bytes        # noqa: E402
from glassballot.election.service import Rejected                   # noqa: E402
from glassballot.election.tally import aggregate                    # noqa: E402
from glassballot.election.verifier import verify_election           # noqa: E402
from glassballot.simulation import Election                         # noqa: E402

BITS = 1024


def new_election(n=3):
    return Election(num_voters=n, paillier_bits=BITS, authority_bits=BITS, voter_bits=1024)


def expect_rejected(label, fn):
    try:
        fn()
        print(f"  !! {label}: NOT rejected")
        return False
    except Rejected as exc:
        print(f"  ok {label}: rejected by service -> {exc}")
        return True


def expect_verifier_fail(label, entries, check_name):
    rep = verify_election(entries)
    failed = [c for c in rep.checks if not c.ok]
    hit = any(c.name == check_name for c in failed)
    detail = failed[0].detail if failed else "no failure"
    print(f"  {'ok' if hit else '!!'} {label}: verifier FAIL [{failed[0].name if failed else '-'}] -> {detail}")
    return hit


def stuffed_ballot(el, voter_index=0):
    """Ballot that encrypts 2 votes for one candidate, reusing an honest proof."""
    v = el.voters[voter_index]
    signed = v.cast(el.params, 0)
    body = signed["body"]
    c2, _ = el.params.paillier_public_key.encrypt(2)
    body["ciphertexts"][0] = int_to_hex(c2)
    signed["signature"] = int_to_hex(v._private_key.sign(ballot_signing_bytes(body)))
    return signed


def main():
    global BITS
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=1024)
    BITS = ap.parse_args().bits
    results = []

    print("Attacks stopped at the service (cast time):")
    el = new_election()
    results.append(expect_rejected("vote stuffing (ciphertext of 2)", lambda: el.service.cast(stuffed_ballot(el))))

    el = new_election()
    v = el.voters[0]
    el.service.cast(v.cast(el.params, 1))
    results.append(expect_rejected("double voting", lambda: el.service.cast(v.cast(el.params, 2))))

    el = new_election()
    a, b = el.voters[0], el.voters[1]
    stolen = copy.deepcopy(a.cast(el.params, 2)["body"])
    stolen["credential_id"] = b.credential["credential_id"]      # B copies A's encrypted vote
    replay = {"body": stolen, "signature": int_to_hex(b._private_key.sign(ballot_signing_bytes(stolen)))}
    results.append(expect_rejected("ballot copied under another credential", lambda: el.service.cast(replay)))

    el = new_election()
    forged = el.voters[0].cast(el.params, 0)
    forged["signature"] = int_to_hex(int(forged["signature"], 16) ^ 1)
    results.append(expect_rejected("forged voter signature", lambda: el.service.cast(forged)))

    print("\nAttacks by a dishonest server or trustee, caught by the public verifier:")
    el = new_election()
    el.cast_all([0, 1, 2])
    el.finish()
    entries = el.board.entries()
    entries[2]["payload"]["voter_public_key"]["e"] = "3"   # edit a stored row
    results.append(expect_verifier_fail("board row edited in the database", entries, "hash chain"))

    el = new_election(4)
    el.cast_all([0, 1, 2])                                    # voters 1-3 vote honestly
    el.board.append("ballot", stuffed_ballot(el, 3))          # server bypasses its own checks
    el.service.close()
    el.service.publish_results(el.trustee)
    results.append(expect_verifier_fail("server injects a stuffed ballot", el.board.entries(), "ballots"))

    el = new_election()
    el.cast_all([0, 0, 1])
    el.service.close()
    p = el.params
    bodies = [e["payload"]["body"] for e in el.board.entries("ballot")][1:]   # drop one ballot
    res = el.trustee.decrypt_tally(p.election_id, p.candidates, aggregate(p.paillier_public_key, bodies, 3))
    el.board.append("result", {"election_id": p.election_id, "results": res})
    results.append(expect_verifier_fail("ballot dropped before tallying", el.board.entries(), "homomorphic tally"))

    el = new_election()
    el.cast_all([0, 1, 1])
    el.service.close()
    p = el.params
    bodies = [e["payload"]["body"] for e in el.board.entries("ballot")]
    res = el.trustee.decrypt_tally(p.election_id, p.candidates, aggregate(p.paillier_public_key, bodies, 3))
    res[0]["total"], res[1]["total"] = res[0]["total"] + 1, res[1]["total"] - 1   # shift a vote
    el.board.append("result", {"election_id": p.election_id, "results": res})
    results.append(expect_verifier_fail("trustee announces a wrong total", el.board.entries(), "decryption proofs"))

    print(f"\n{sum(results)}/{len(results)} attacks caught")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
