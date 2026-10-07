"""M6 - Independent public verification.

Input: the bulletin-board entries, nothing else. No private key, no access to
the service. Re-derives and re-checks every claim the service made:

  1. hash chain intact (nothing edited, inserted or deleted)
  2. board structure: election first, then credentials/ballots, close, result
  3. every credential signed by the authority, no duplicates
  4. every ballot: registered credential, first ballot for that credential,
     valid voter signature, valid 0-or-1 and sum-equals-1 proofs
  5. close entry matches the number of ballots
  6. encrypted totals recomputed from the ballots equal the posted ones
  7. every decryption proof verifies; totals add up to the ballot count
"""

from dataclasses import dataclass, field

from ..crypto.encoding import hex_to_int
from ..crypto.proofs import verify_decryption
from ..crypto.rsa import RSAPublicKey
from .authority import verify_credential
from .ballot import InvalidBallot, ballot_signing_bytes, verify_ballot_body
from .bulletin_board import verify_chain
from .params import ElectionParams
from .tally import aggregate, decryption_context


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class VerificationReport:
    checks: list = field(default_factory=list)
    results: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    def add(self, name, ok, detail):
        self.checks.append(Check(name, ok, detail))
        return ok

    def render(self) -> str:
        lines = [f"[{'PASS' if c.ok else 'FAIL'}] {c.name}: {c.detail}" for c in self.checks]
        if self.ok and self.results:
            lines.append("Verified result: " + ", ".join(f"{r['name']} = {r['total']}" for r in self.results))
        lines.append("ELECTION VERIFIED" if self.ok else "ELECTION NOT VERIFIED")
        return "\n".join(lines)


def verify_election(entries) -> VerificationReport:
    rep = VerificationReport()

    ok, reason = verify_chain(entries)
    if not rep.add("hash chain", ok, reason):
        return rep  # nothing after a broken chain can be trusted

    # -- structure
    kinds = [e["kind"] for e in entries]
    order_ok = (
        kinds[:1] == ["election"]
        and kinds.count("election") == 1
        and kinds.count("close") == 1
        and kinds.count("result") == 1
        and kinds[-1] == "result" and kinds[-2] == "close"
    )
    if not rep.add("board structure", order_ok,
                   "election -> credentials/ballots -> close -> result" if order_ok
                   else f"unexpected entry order {kinds[:3]}...{kinds[-2:]}"):
        return rep
    try:
        params = ElectionParams.from_dict(entries[0]["payload"])
    except (KeyError, TypeError, ValueError) as exc:
        rep.add("election parameters", False, f"unparseable: {exc}")
        return rep
    pk, eid = params.paillier_public_key, params.election_id

    # -- credentials and ballots, in board order
    roll, voted, accepted, bad_creds, bad_ballots = {}, set(), [], [], []
    for e in entries[1:-2]:
        p = e["payload"]
        if e["kind"] == "credential":
            if not verify_credential(params.authority_public_key, p, eid) or p["credential_id"] in roll:
                bad_creds.append(e["seq"])
            else:
                roll[p["credential_id"]] = p
        elif e["kind"] == "ballot":
            problem = _check_ballot(p, params, roll, voted)
            if problem:
                bad_ballots.append(f"#{e['seq']} ({problem})")
            else:
                voted.add(p["body"]["credential_id"])
                accepted.append(p["body"])
        else:
            bad_ballots.append(f"#{e['seq']} (unexpected {e['kind']} entry)")

    rep.add("voter roll", not bad_creds,
            f"{len(roll)} credentials signed by the authority" if not bad_creds
            else f"invalid credential entries {bad_creds}")
    rep.add("ballots", not bad_ballots,
            f"{len(accepted)} ballots, all signed, proven well-formed, one per credential"
            if not bad_ballots else "invalid: " + "; ".join(bad_ballots[:5]))

    close = entries[-2]["payload"]
    rep.add("close entry", close.get("ballot_count") == len(accepted) and close.get("election_id") == eid,
            f"announced {close.get('ballot_count')} ballots, board holds {len(accepted)}")

    # -- tally
    totals = aggregate(pk, accepted, params.num_candidates)
    posted = entries[-1]["payload"].get("results", [])
    tally_ok, decrypt_ok, details = len(posted) == params.num_candidates, True, []
    for i, r in enumerate(posted if tally_ok else []):
        try:
            c, m = hex_to_int(r["encrypted_total"]), r["total"]
        except (KeyError, TypeError, ValueError):
            tally_ok = False
            continue
        if r.get("candidate") != i or c != totals[i]:
            tally_ok = False
            details.append(f"candidate {i}: posted encrypted total != product of ballots")
        if not verify_decryption(pk, c, m, r.get("proof", {}), decryption_context(eid, i)):
            decrypt_ok = False
            details.append(f"candidate {i}: decryption proof invalid for total {m}")
    rep.add("homomorphic tally", tally_ok,
            "encrypted totals match the product of all accepted ballots" if tally_ok
            else "; ".join(d for d in details if "product" in d) or "results malformed")
    rep.add("decryption proofs", decrypt_ok,
            "every announced total is the true decryption" if decrypt_ok
            else "; ".join(d for d in details if "decryption" in d))
    if tally_ok and decrypt_ok:
        s = sum(r["total"] for r in posted)
        rep.add("totals consistent", s == len(accepted), f"sum of totals {s}, ballots {len(accepted)}")
        rep.results = [{"name": r["name"], "total": r["total"]} for r in posted]
    return rep


def _check_ballot(signed: dict, params: ElectionParams, roll: dict, voted: set):
    """Return None if valid, else a short reason."""
    try:
        body, sig = signed["body"], hex_to_int(signed["signature"])
        cred_id = body["credential_id"]
    except (KeyError, TypeError, ValueError):
        return "malformed"
    if cred_id not in roll:
        return "credential not registered"
    if cred_id in voted:
        return "second ballot for credential"
    if not RSAPublicKey.from_dict(roll[cred_id]["voter_public_key"]).verify(ballot_signing_bytes(body), sig):
        return "bad voter signature"
    try:
        verify_ballot_body(params.paillier_public_key, params.election_id, params.num_candidates, body)
    except InvalidBallot as exc:
        return str(exc)
    return None
