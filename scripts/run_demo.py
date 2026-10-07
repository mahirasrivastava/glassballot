#!/usr/bin/env python3
"""End-to-end demo: key ceremony -> registration -> casting -> tally -> public verification.

    python scripts/run_demo.py --voters 10 --board out/board.jsonl
    python scripts/verify_board.py out/board.jsonl
"""

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from glassballot.election.bulletin_board import load_entries  # noqa: E402
from glassballot.election.verifier import verify_election     # noqa: E402
from glassballot.simulation import DEFAULT_CANDIDATES, Election  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--voters", type=int, default=10)
    ap.add_argument("--candidates", nargs="+", default=list(DEFAULT_CANDIDATES))
    ap.add_argument("--paillier-bits", type=int, default=2048)
    ap.add_argument("--authority-bits", type=int, default=2048)
    ap.add_argument("--voter-bits", type=int, default=1024)
    ap.add_argument("--board", default="out/board.jsonl", help="bulletin board file (overwritten)")
    ap.add_argument("--seed", type=int, help="seed for the simulated voters' choices only")
    args = ap.parse_args()

    board_path = Path(args.board)
    if board_path.exists():
        board_path.unlink()

    t0 = time.perf_counter()
    print(f"[1] Key ceremony + registering {args.voters} voters "
          f"(Paillier {args.paillier_bits}-bit, RSA {args.authority_bits}/{args.voter_bits}-bit)...")
    el = Election(args.voters, tuple(args.candidates), args.paillier_bits,
                  args.authority_bits, args.voter_bits, board_path)
    print(f"    election {el.params.election_id}: {el.params.title}, candidates {list(el.params.candidates)}")

    rng = random.Random(args.seed)
    choices = [rng.randrange(len(args.candidates)) for _ in el.voters]
    print("[2] Casting encrypted ballots with ZK well-formedness proofs...")
    t1 = time.perf_counter()
    receipts = el.cast_all(choices)
    per_ballot = (time.perf_counter() - t1) / max(1, len(receipts))
    print(f"    {len(receipts)} ballots accepted, {per_ballot * 1000:.0f} ms per ballot (encrypt+prove+check)")
    print(f"    sample receipt: {receipts[0][:32]}...")

    print("[3] Closing election; trustee decrypts each homomorphic total once, with proofs...")
    for r in el.finish():
        print(f"    {r['name']:>10}: {r['total']}")
    expected = [choices.count(i) for i in range(len(args.candidates))]
    print(f"    (ground truth from the simulation: {expected})")

    print(f"[4] Independent verification of {board_path} (public data only)...")
    report = verify_election(load_entries(board_path))
    print("    " + report.render().replace("\n", "\n    "))
    print(f"Done in {time.perf_counter() - t0:.1f}s")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
