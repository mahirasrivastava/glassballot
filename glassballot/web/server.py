"""HTTP API + static voting booth, standard library only (stand-in for the planned Flask app).

One election lives in memory at a time. The server plays every role the CLI
demo plays (authority, trustee, voters' devices), so ballots are encrypted
server-side for now; the browser only picks a candidate. Everything the public
would see goes through the bulletin board, and /api/verify runs the same
independent verifier as scripts/verify_board.py.

    GET  /api/state           election, voters, phase, results
    POST /api/election        {title, candidates[], voters, paillier_bits}
    POST /api/vote            {voter, choice}  -> receipt
    POST /api/close           close + homomorphic tally + decryption proofs
    GET  /api/board           bulletin-board entries
    GET  /api/board.jsonl     the board as a file (check it with verify_board.py)
    GET  /api/verify          public verification report
    POST /api/receipt         {receipt} -> where that ballot sits on the board
"""

import json
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..election.ballot import ballot_hash
from ..election.service import Rejected
from ..election.verifier import verify_election
from ..simulation import Election

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_VOTERS = 50
PAILLIER_SIZES = (1024, 2048)


class ApiError(Exception):
    def __init__(self, message, status=HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


class ElectionHost:
    """Holds the current in-memory election; every method runs under one lock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.election = None
        self.results = None

    # ---------------------------------------------------------------- views
    def state(self) -> dict:
        el = self.election
        if el is None:
            return {"phase": "none"}
        p = el.params
        return {
            "phase": "tallied" if self.results is not None else "open",
            "election_id": p.election_id,
            "title": p.title,
            "candidates": list(p.candidates),
            "voters": [{"index": i, "name": v.name,
                        "credential_id": v.credential["credential_id"],
                        "receipt": v.receipt}
                       for i, v in enumerate(el.voters)],
            "board_length": len(el.board),
            "board_head": el.board.head,
            "results": [{"name": r["name"], "total": r["total"]} for r in self.results or []],
        }

    def board(self) -> list:
        return self.election.board.entries() if self.election else []

    # -------------------------------------------------------------- actions
    def create(self, body: dict) -> dict:
        title = str(body.get("title") or "").strip() or "Demo election"
        candidates = [str(c).strip() for c in body.get("candidates", []) if str(c).strip()]
        if len(candidates) < 2:
            raise ApiError("need at least two candidates")
        if len(set(candidates)) != len(candidates):
            raise ApiError("candidate names must be unique")
        voters = _int(body.get("voters", 5), "voters")
        if not 1 <= voters <= MAX_VOTERS:
            raise ApiError(f"voters must be between 1 and {MAX_VOTERS}")
        bits = _int(body.get("paillier_bits", 2048), "paillier_bits")
        if bits not in PAILLIER_SIZES:
            raise ApiError(f"paillier_bits must be one of {PAILLIER_SIZES}")
        t0 = time.perf_counter()
        self.election = Election(voters, tuple(candidates), paillier_bits=bits, title=title)
        self.results = None
        return {"seconds": round(time.perf_counter() - t0, 2), **self.state()}

    def vote(self, body: dict) -> dict:
        el = self._require_election()
        index = _int(body.get("voter"), "voter")
        choice = _int(body.get("choice"), "choice")
        if not 0 <= index < len(el.voters):
            raise ApiError("no such voter")
        if not 0 <= choice < el.params.num_candidates:
            raise ApiError("no such candidate")
        voter = el.voters[index]
        previous_receipt = voter.receipt
        t0 = time.perf_counter()
        signed = voter.cast(el.params, choice)
        try:
            receipt = el.service.cast(signed)
        except Rejected as exc:
            voter.receipt = previous_receipt  # the rejected ballot never reached the board
            raise ApiError(f"rejected: {exc}", HTTPStatus.CONFLICT)
        return {"receipt": receipt, "seconds": round(time.perf_counter() - t0, 2)}

    def close(self) -> dict:
        el = self._require_election()
        if self.results is not None:
            raise ApiError("election already tallied", HTTPStatus.CONFLICT)
        try:
            self.results = el.finish()
        except Rejected as exc:
            raise ApiError(f"rejected: {exc}", HTTPStatus.CONFLICT)
        return self.state()

    def verify(self) -> dict:
        el = self._require_election()
        if self.results is None:
            raise ApiError("the verifier checks a finished election: close it first", HTTPStatus.CONFLICT)
        report = verify_election(el.board.entries())
        return {"ok": report.ok, "results": report.results,
                "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in report.checks]}

    def find_receipt(self, body: dict) -> dict:
        el = self._require_election()
        receipt = str(body.get("receipt") or "").strip().lower()
        if not receipt:
            raise ApiError("enter a receipt")
        for e in el.board.entries("ballot"):
            if ballot_hash(e["payload"]) == receipt:
                return {"found": True, "seq": e["seq"], "entry_hash": e["entry_hash"]}
        return {"found": False}

    def _require_election(self) -> Election:
        if self.election is None:
            raise ApiError("no election yet", HTTPStatus.CONFLICT)
        return self.election


def _int(value, name) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ApiError(f"{name} must be an integer")


class Handler(SimpleHTTPRequestHandler):
    host = None  # ElectionHost, set by make_server

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, fmt, *args):
        if not self.path.startswith("/api/state"):
            super().log_message(fmt, *args)

    def do_GET(self):
        routes = {
            "/api/state": self.host.state,
            "/api/board": self.host.board,
            "/api/verify": self.host.verify,
        }
        path = self.path.split("?", 1)[0]
        if path == "/api/board.jsonl":
            with self.host.lock:
                text = "".join(json.dumps(e, sort_keys=True) + "\n" for e in self.host.board())
            return self._send(HTTPStatus.OK, text.encode(), "application/x-ndjson",
                              {"Content-Disposition": 'attachment; filename="board.jsonl"'})
        if path in routes:
            return self._call(routes[path])
        if path.startswith("/api/"):
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        return super().do_GET()

    def do_POST(self):
        routes = {
            "/api/election": self.host.create,
            "/api/vote": self.host.vote,
            "/api/close": lambda _body: self.host.close(),
            "/api/receipt": self.host.find_receipt,
        }
        handler = routes.get(self.path.split("?", 1)[0])
        if handler is None:
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
        self._call(lambda: handler(body))

    def _call(self, fn):
        try:
            with self.host.lock:
                result = fn()
        except ApiError as exc:
            return self._json(exc.status, {"error": str(exc)})
        self._json(HTTPStatus.OK, result)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj).encode(), "application/json")

    def _send(self, status, data, content_type, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


def make_server(host="127.0.0.1", port=8000) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"host": ElectionHost()})
    return ThreadingHTTPServer((host, port), handler)
