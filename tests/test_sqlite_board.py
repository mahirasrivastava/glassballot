import sqlite3
import tempfile
import unittest
from pathlib import Path

from tests.fixtures import TEST_PAILLIER_BITS, TEST_RSA_BITS

from glassballot.election.sqlite_board import SQLiteBoard, connect, list_boards, load_sqlite_entries
from glassballot.election.verifier import verify_election
from glassballot.simulation import Election


class TestSQLiteBoard(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "gb.db"
        self.conn = connect(self.path)

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def test_persists_and_reloads(self):
        board = SQLiteBoard(self.conn)
        for i in range(3):
            board.append("credential", {"i": i})
        again = SQLiteBoard(connect(self.path), board.board_id)   # reload re-checks the chain
        self.assertEqual(again.entries(), board.entries())
        self.assertEqual(again.head, board.head)

    def test_update_and_delete_blocked_by_triggers(self):
        board = SQLiteBoard(self.conn)
        board.append("credential", {"i": 1})
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE board_entries SET payload = '{\"i\": 2}'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM board_entries")
        self.assertEqual(len(load_sqlite_entries(self.conn, board.board_id)), 1)

    def test_tampering_around_triggers_detected_on_open(self):
        board = SQLiteBoard(self.conn)
        for i in range(3):
            board.append("credential", {"i": i})
        self.conn.execute("DROP TRIGGER board_entries_no_update")   # an attacker with the file can do this
        self.conn.execute("UPDATE board_entries SET payload = '{\"i\": 9}' WHERE seq = 1")
        with self.assertRaises(ValueError):
            SQLiteBoard(self.conn, board.board_id)

    def test_database_allows_one_ballot_per_credential(self):
        board = SQLiteBoard(self.conn)
        board.append("ballot", {"body": {"credential_id": "abc"}, "signature": "1"})
        with self.assertRaises(sqlite3.IntegrityError):
            board.append("ballot", {"body": {"credential_id": "abc"}, "signature": "2"})
        self.assertEqual(len(board), 1)   # the failed insert never reached the in-memory copy

    def test_boards_are_independent(self):
        a, b = SQLiteBoard(self.conn), SQLiteBoard(self.conn)
        a.append("credential", {"i": 1})
        b.append("credential", {"i": 2})
        b.append("credential", {"i": 3})
        self.assertEqual(len(a), 1)
        self.assertEqual({x["board_id"]: x["entries"] for x in list_boards(self.conn)}, {a.board_id: 1, b.board_id: 2})

    def test_full_election_verifies_from_database(self):
        el = Election(3, ("A", "B"), TEST_PAILLIER_BITS, TEST_RSA_BITS, TEST_RSA_BITS,
                      board=SQLiteBoard(self.conn))
        el.cast_all([1, 0, 1])
        el.finish()
        rep = verify_election(load_sqlite_entries(self.conn, el.board.board_id))
        self.assertTrue(rep.ok, rep.render())
        self.assertEqual([r["total"] for r in rep.results], [1, 2])
        [stored] = list_boards(self.conn)
        self.assertEqual((stored["ballots"], stored["tallied"], stored["election_id"]),
                         (3, True, el.params.election_id))


if __name__ == "__main__":
    unittest.main()
