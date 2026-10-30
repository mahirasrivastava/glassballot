#!/usr/bin/env python3
"""Public verifier CLI. Needs only the bulletin-board file - no keys, no server.

    python scripts/verify_board.py out/board.jsonl
    python scripts/verify_board.py out/glassballot.db              # newest election in the database
    python scripts/verify_board.py out/glassballot.db --list       # every election stored there
    python scripts/verify_board.py out/glassballot.db --board-id ID
Exit code 0 = election verified, 1 = verification failed.
"""

import argparse
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from glassballot.election.bulletin_board import load_entries  # noqa: E402
from glassballot.election.sqlite_board import connect, list_boards, load_sqlite_entries  # noqa: E402
from glassballot.election.verifier import verify_election     # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("board", help="bulletin board .jsonl file, or a SQLite .db written by serve.py")
    ap.add_argument("--board-id", help="which election in a .db file (default: the newest)")
    ap.add_argument("--list", action="store_true", help="list the elections in a .db file and exit")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1, help="processes checking ballot proofs")
    args = ap.parse_args()

    if Path(args.board).suffix in (".db", ".sqlite", ".sqlite3"):
        if not Path(args.board).exists():
            ap.error(f"{args.board} does not exist")
        conn = connect(args.board)
        boards = list_boards(conn)
        if args.list:
            for b in boards:
                print(f"{b['board_id']}  {b['created_at']}  {b['entries']:>4} entries  "
                      f"{'tallied' if b['tallied'] else 'open   '}  {b['title']}")
            return 0
        if not boards:
            ap.error("no elections in that database")
        board_id = args.board_id or boards[0]["board_id"]
        entries = load_sqlite_entries(conn, board_id)
        if not entries:
            ap.error(f"no election with board id {board_id}")
        print(f"Board {board_id} from {args.board}\n")
    else:
        entries = load_entries(args.board)

    if args.workers > 1:
        with ProcessPoolExecutor(args.workers) as pool:
            report = verify_election(entries, pool)
    else:
        report = verify_election(entries)
    print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
