#!/usr/bin/env python3
"""Public verifier CLI. Needs only the bulletin-board file - no keys, no server.

    python scripts/verify_board.py out/board.jsonl
Exit code 0 = election verified, 1 = verification failed.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from glassballot.election.bulletin_board import load_entries  # noqa: E402
from glassballot.election.verifier import verify_election     # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("board", help="path to the bulletin board .jsonl file")
    args = ap.parse_args()
    report = verify_election(load_entries(args.board))
    print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
