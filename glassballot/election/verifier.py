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
  7. every total is opened: the k trustees' partials multiply to R and
     g^m * R^n = T (mod n^2); totals add up to the ballot count
"""

from dataclasses import dataclass, field

from ..crypto.encoding import hex_to_int
from ..crypto.rsa import RSAPublicKey
from .authority import verify_credential
from .ballot import InvalidBallot, ballot_signing_bytes, verify_ballot_body
from .bulletin_board import verify_chain
from .params import ElectionParams
from .tally import aggregate, check_opening


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


def verify_election(entries, executor=None) -> VerificationReport:
    """executor: optional concurrent.futures executor; the per-ballot signature and proof
    checks (the expensive part, independent of each other) are spread across it."""
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

    # -- credentials and ballots, in board order (cheap, sequential checks)
    roll, voted, pending, bad_creds, bad_ballots = {}, set(), [], [], []
    for e in entries[1:-2]:
        p = e["payload"]
        if e["kind"] == "credential":
            if not verify_credential(params.authority_public_key, p, eid) or p["credential_id"] in roll:
                bad_creds.append(e["seq"])
            else:
                roll[p["credential_id"]] = p
        elif e["kind"] == "ballot":
            problem = _ballot_precheck(p, roll, voted)
            if problem:
                bad_ballots.append(f"#{e['seq']} ({problem})")
            else:
                voted.add(p["body"]["credential_id"])
                pending.append(e)
        else:
            bad_ballots.append(f"#{e['seq']} (unexpected {e['kind']} entry)")

    # -- signatures and proofs (expensive, independent: parallel when an executor is given)
    jobs = [(entries[0]["payload"], roll[e["payload"]["body"]["credential_id"]]["voter_public_key"], e["payload"])
            for e in pending]
    problems = list(executor.map(_ballot_crypto, jobs, chunksize=max(1, len(jobs) // 64)) if executor and jobs
                    else map(_ballot_crypto, jobs))
    accepted = []
    for e, problem in zip(pending, problems):
        if problem:
            bad_ballots.append(f"#{e['seq']} ({problem})")
        else:
            accepted.append(e["payload"]["body"])

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
            c, m, rand = hex_to_int(r["encrypted_total"]), r["total"], hex_to_int(r["randomness"])
            partials = [hex_to_int(x) for x in r["partials"]]
        except (KeyError, TypeError, ValueError):
            tally_ok = False
            details.append(f"candidate {i}: result entry malformed")
            continue
        if r.get("candidate") != i or c != totals[i]:
            tally_ok = False
            details.append(f"candidate {i}: posted encrypted total != product of ballots")
        product = 1
        for x in partials:
            product = product * x % pk.n
        if len(partials) != params.trustees or product != rand:
            decrypt_ok = False
            details.append(f"candidate {i}: randomness is not the product of {params.trustees} trustee partials")
        elif not check_opening(pk, c, m, rand):
            decrypt_ok = False
            details.append(f"candidate {i}: g^m * R^n != total for announced m = {m}")
    rep.add("homomorphic tally", tally_ok,
            "encrypted totals match the product of all accepted ballots" if tally_ok
            else "; ".join(d for d in details if "product of ballots" in d) or "results malformed")
    rep.add("decryption proofs", decrypt_ok,
            f"every total opened by all {params.trustees} trustees' partials: g^m * R^n = T" if decrypt_ok
            else "; ".join(d for d in details if "product of ballots" not in d) or "results malformed")
    if tally_ok and decrypt_ok:
        s = sum(r["total"] for r in posted)
        rep.add("totals consistent", s == len(accepted), f"sum of totals {s}, ballots {len(accepted)}")
        rep.results = [{"name": r["name"], "total": r["total"]} for r in posted]
    return rep


def _ballot_precheck(signed: dict, roll: dict, voted: set):
    """Structure, registration and one-ballot-per-credential. None if fine, else a short reason."""
    try:
        cred_id = signed["body"]["credential_id"]
        hex_to_int(signed["signature"])
        hash(cred_id)
    except (KeyError, TypeError, ValueError):
        return "malformed"
    if cred_id not in roll:
        return "credential not registered"
    if cred_id in voted:
        return "second ballot for credential"
    return None


def _ballot_crypto(job):
    """Voter signature and every ballot proof. Pure, so it can run in another process."""
    params_dict, voter_key, signed = job
    params = ElectionParams.from_dict(params_dict)
    body = signed["body"]
    if not RSAPublicKey.from_dict(voter_key).verify(ballot_signing_bytes(body), hex_to_int(signed["signature"])):
        return "bad voter signature"
    try:
        verify_ballot_body(params.paillier_public_key, params.election_id, params.num_candidates, body)
    except InvalidBallot as exc:
        return str(exc)
    return None
