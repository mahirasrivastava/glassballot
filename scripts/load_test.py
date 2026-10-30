#!/usr/bin/env python3
"""Load test: many voters casting at once against a running server.

    python3 scripts/serve.py --rate 0 &            # one client IP sends everything, so lift the limit
    python3 scripts/load_test.py --voters 200 --concurrency 32

1. Prepare (not timed): create an election, register every voter, build every signed
   ballot. Key generation and encryption run in a process pool, like many devices would.
2. Storm (timed): send all ballots concurrently; report throughput and latency.
3. Finish: close, let the trustees decrypt, run the public verifier on the full board.
"""

import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from glassballot.election.params import ElectionParams   # noqa: E402
from glassballot.election.tally import Trustee            # noqa: E402
from glassballot.election.voter import Voter              # noqa: E402
from glassballot.simulation import board_totals           # noqa: E402

BASE = "http://127.0.0.1:8000"


def call(path, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=600) as res:
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def new_voter(_):
    v = Voter("load", 2048)
    return v


def make_ballot(args):
    voter, params_dict, choice = args
    return voter.cast(ElectionParams.from_dict(params_dict), choice)


def main():
    global BASE
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=BASE)
    ap.add_argument("--voters", type=int, default=100)
    ap.add_argument("--concurrency", type=int, default=32, help="ballots in flight at once")
    ap.add_argument("--bits", type=int, default=2048, choices=(1024, 2048), help="Paillier modulus size")
    ap.add_argument("--trustees", type=int, default=3)
    args = ap.parse_args()
    BASE = args.url.rstrip("/")
    cores = os.cpu_count() or 1

    print(f"[1] Preparing {args.voters} voters on {cores} cores (not timed)...")
    t0 = time.perf_counter()
    status, made = call("/api/election", {"title": "Load test", "candidates": ["A", "B", "C"], "voters": args.voters,
                                          "paillier_bits": args.bits, "trustees": args.trustees})
    if status != 200:
        sys.exit(f"could not create the election: {made}")
    _, entries = call("/api/board")
    params = entries[0]["payload"]
    with ProcessPoolExecutor() as pool:
        voters = list(pool.map(new_voter, range(args.voters), chunksize=4))
        for v, c in zip(voters, made["codes"]):
            status, res = call("/api/register", {"code": c["code"], "voter_public_key": v.public_key.to_dict()})
            if status == 429:
                sys.exit("rate limited: start the server with --rate 0 for a load test")
            if status != 200:
                sys.exit(f"registration failed: {res}")
            v.receive_credential(res["credential"])
        choices = [i % 3 for i in range(args.voters)]
        ballots = list(pool.map(make_ballot, [(v, params, c) for v, c in zip(voters, choices)], chunksize=4))
    print(f"    ready in {time.perf_counter() - t0:.1f}s")

    print(f"[2] Casting {len(ballots)} ballots, {args.concurrency} at a time...")

    def cast(ballot):
        t = time.perf_counter()
        status, res = call("/api/vote", {"ballot": ballot})
        return status, time.perf_counter() - t, res

    t1 = time.perf_counter()
    with ThreadPoolExecutor(args.concurrency) as threads:
        outcomes = list(threads.map(cast, ballots))
    wall = time.perf_counter() - t1
    ok = [lat for s, lat, _ in outcomes if s == 200]
    bad = [(s, r.get("error")) for s, _, r in outcomes if s != 200]
    lat = sorted(ok)
    print(f"    accepted {len(ok)}/{len(ballots)} in {wall:.1f}s  ->  {len(ok) / wall:.1f} ballots/s "
          f"({len(ok) / wall * 3600:,.0f} per hour)")
    if lat:
        print(f"    latency  p50 {statistics.median(lat):.2f}s  p95 {lat[int(0.95 * (len(lat) - 1))]:.2f}s  max {lat[-1]:.2f}s")
    if bad:
        print(f"    rejected: {bad[:3]}{' ...' if len(bad) > 3 else ''}")

    print("[3] Closing, trustee decryption, public verification...")
    admin = {"X-Admin-Token": made["admin_token"]}
    call("/api/close", {}, admin)
    t2 = time.perf_counter()
    _, entries = call("/api/board")
    totals = board_totals(entries)
    for share in made["trustee_shares"]:
        partials = Trustee.from_export(share).partial_decrypt(totals)
        status, res = call("/api/trustee/partial", {"trustee": share["trustee"], "token": share["token"], "partials": partials})
        if status != 200:
            sys.exit(f"trustee {share['trustee'] + 1} failed: {res}")
    print(f"    tally opened in {time.perf_counter() - t2:.1f}s: {res['results']}")
    expected = [choices[:len(ok)].count(i) for i in range(3)] if not bad else None
    t3 = time.perf_counter()
    _, report = call("/api/verify")
    print(f"    verifier: {'ELECTION VERIFIED' if report['ok'] else 'FAILED'} in {time.perf_counter() - t3:.1f}s "
          f"({len(entries)} board entries)")
    if expected and [r["total"] for r in res["results"]] != expected:
        sys.exit(f"tally mismatch: expected {expected}")
    return 0 if report["ok"] and not bad else 1


if __name__ == "__main__":
    sys.exit(main())
