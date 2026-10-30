"""HTTP API + static web app, standard library only (stand-in for a Flask/FastAPI deployment).

Who holds what (the server is never trusted with a vote or with the decryption key):

  voter        RSA private key, generated in the browser and never sent. Ballots are
               encrypted, proven and signed in the browser (static/gbcrypto.js).
  authority    signs credentials; acts through an admin token (only its hash is kept).
  trustees     one share of the decryption key each, handed out once at creation;
               the server keeps none, so it cannot decrypt anything on its own.
  public       everything on the bulletin board; /api/verify re-checks it.

Endpoints (POST bodies are JSON objects):
    GET  /api/state                     public summary of the current election
    POST /api/election            [O]   {title, candidates[], voters, paillier_bits, trustees}
                                        -> admin token, registration codes, trustee shares (shown once)
    GET  /api/admin/roll          [A]   registration codes and their status
    POST /api/close               [A]   close the polls
    POST /api/register                  {code, voter_public_key} -> credential signed by the authority
    POST /api/vote                      {ballot} signed + encrypted in the browser -> receipt
    POST /api/audit                     {body, choice, randomness} -> does a spoiled ballot open as claimed
    POST /api/trustee/partial           {trustee, token, partials[]}; the last one publishes the result
    GET  /api/board[?since=N]           bulletin-board entries (incrementally)
    GET  /api/board.jsonl               the board as a file (check it with verify_board.py)
    GET  /api/verify                    public verification report
    POST /api/receipt                   {receipt} -> where that ballot sits on the board
    GET  /api/elections                 every board stored in the SQLite database
    GET  /api/elections/<id>/verify | /board.jsonl
[A] = needs the X-Admin-Token header.
[O] = needs the X-Organizer-Key header when the server was started with an organizer key
      (--organizer-key / $GLASSBALLOT_ORGANIZER_KEY). Without one, anyone may start an election (local demo).

Ballot checks (~0.7 s each at 2048 bits) run in a process pool outside the lock;
only "not yet voted -> append" is serialised. POSTs are rate-limited per client IP.
"""

import hashlib
import hmac
import json
import secrets
import ssl
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..crypto.encoding import hex_to_int
from ..crypto.rsa import RSAPublicKey
from ..election.authority import ElectionAuthority
from ..election.ballot import InvalidBallot, verify_ballot_body
from ..election.bulletin_board import BulletinBoard
from ..election.service import ElectionService, Rejected, check_ballot
from ..election.sqlite_board import SQLiteBoard, connect, list_boards, load_sqlite_entries
from ..election.tally import key_ceremony
from ..election.verifier import verify_election

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_VOTERS = 5000
MAX_TRUSTEES = 7
MAX_BODY = 2 * 1024 * 1024
PAILLIER_SIZES = (1024, 2048, 3072)
AUTHORITY_BITS = 2048
MIN_VOTER_KEY_BITS = 2048
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O, 1/I

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; "
                                "form-action 'self'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class ApiError(Exception):
    def __init__(self, message, status=HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _new_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))
    return "-".join(raw[i:i + 4] for i in range(0, 12, 4))


def _normalise_code(code) -> str:
    raw = "".join(ch for ch in str(code or "").upper() if ch.isalnum())
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


class HostedElection:
    """One election as the web server runs it. The constructor is the key ceremony."""

    def __init__(self, title, candidates, voters, paillier_bits, trustees, board):
        self.board = board
        self.service = ElectionService(board)
        self.authority = ElectionAuthority(AUTHORITY_BITS)
        paillier_pk, trustee_objs = key_ceremony(paillier_bits, trustees)
        self.params = self.service.create_election(title, candidates, self.authority.public_key,
                                                   paillier_pk, trustees)
        self.params_dict = self.params.to_dict()
        self.paillier_bits = paillier_bits

        admin_token = secrets.token_urlsafe(24)
        self.admin_digest = _digest(admin_token)
        self.roll = [{"name": f"voter-{i + 1}", "code": _new_code(), "credential_id": None} for i in range(voters)]
        self.by_code = {_digest(v["code"]): v for v in self.roll}

        shares = []
        self.trustee_digests = []
        for t in trustee_objs:
            token = secrets.token_urlsafe(24)
            self.trustee_digests.append(_digest(token))
            shares.append({**t.export(), "token": token, "election_id": self.params.election_id,
                           "title": title, "of": trustees})
        del trustee_objs   # the server keeps no share
        self.partials = {}
        self.results = None
        # Returned to the creator exactly once.
        self.handover = {"admin_token": admin_token, "trustee_shares": shares,
                         "codes": [{"name": v["name"], "code": v["code"]} for v in self.roll]}

    @property
    def phase(self) -> str:
        if self.results is not None:
            return "tallied"
        return "closed" if self.service.closed else "open"

    def is_admin(self, token) -> bool:
        return isinstance(token, str) and hmac.compare_digest(_digest(token), self.admin_digest)


class ElectionHost:
    """The current election plus the stored ones; every state change runs under one lock."""

    def __init__(self, db_path=None, workers=0, organizer_key=None):
        self.lock = threading.Lock()
        self.organizer_digest = _digest(organizer_key) if organizer_key else None
        self.election = None
        self.db_path = db_path
        self.db = connect(db_path) if db_path else None
        self.pool = ProcessPoolExecutor(max_workers=workers) if workers else None
        self.reports = {}                  # board head -> verification report
        self.cache_lock = threading.Lock()

    # ---------------------------------------------------------------- views
    def state(self) -> dict:
        el = self.election
        base = {"storage": self._storage(), "organizer_key_required": self.organizer_digest is not None}
        if el is None:
            return {"phase": "none", **base}
        p = el.params
        return {
            **base,
            "phase": el.phase,
            "election_id": p.election_id,
            "title": p.title,
            "candidates": list(p.candidates),
            "paillier_bits": el.paillier_bits,
            "trustees": p.trustees,
            "trustees_submitted": [j in el.partials for j in range(p.trustees)],
            "voters": len(el.roll),
            "registered": sum(1 for v in el.roll if v["credential_id"]),
            "ballots": el.service.ballot_count,
            "board_length": len(el.board),
            "board_head": el.board.head,
            "board_id": getattr(el.board, "board_id", None),
            "results": [{"name": r["name"], "total": r["total"]} for r in el.results or []],
        }

    def _storage(self) -> str:
        return f"SQLite · {self.db_path}" if self.db else "memory"

    def board(self, since=0) -> list:
        el = self.election
        if el is None:
            return []
        return el.board.entries(since=since)

    # -------------------------------------------------------------- authority
    def check_organizer(self, key) -> None:
        if self.organizer_digest is None:
            return
        if not isinstance(key, str) or not hmac.compare_digest(_digest(key), self.organizer_digest):
            raise ApiError("starting an election needs the organizer key", HTTPStatus.FORBIDDEN)

    def create(self, body: dict, organizer_key=None) -> dict:
        self.check_organizer(organizer_key)
        title = str(body.get("title") or "").strip()[:80] or "Demo election"
        candidates = [str(c).strip()[:40] for c in body.get("candidates", []) if str(c).strip()]
        if len(candidates) < 2:
            raise ApiError("need at least two candidates")
        if len(candidates) > 12:
            raise ApiError("at most 12 candidates")
        if len(set(candidates)) != len(candidates):
            raise ApiError("candidate names must be unique")
        voters = _int(body.get("voters", 5), "voters")
        if not 1 <= voters <= MAX_VOTERS:
            raise ApiError(f"voters must be between 1 and {MAX_VOTERS}")
        bits = _int(body.get("paillier_bits", 2048), "paillier_bits")
        if bits not in PAILLIER_SIZES:
            raise ApiError(f"paillier_bits must be one of {PAILLIER_SIZES}")
        trustees = _int(body.get("trustees", 3), "trustees")
        if not 1 <= trustees <= MAX_TRUSTEES:
            raise ApiError(f"trustees must be between 1 and {MAX_TRUSTEES}")
        t0 = time.perf_counter()
        board = SQLiteBoard(self.db) if self.db else BulletinBoard()
        self.election = HostedElection(title, candidates, voters, bits, trustees, board)
        handover = self.election.handover
        self.election.handover = None
        return {"seconds": round(time.perf_counter() - t0, 2), **handover, **self.state()}

    def admin_roll(self, token) -> list:
        el = self._require_admin(token)
        return [{"name": v["name"], "code": v["code"], "registered": bool(v["credential_id"]),
                 "credential_id": v["credential_id"],
                 "voted": bool(v["credential_id"]) and el.service.has_voted(v["credential_id"])}
                for v in el.roll]

    def close(self, token) -> dict:
        el = self._require_admin(token)
        try:
            el.service.close()
        except Rejected as exc:
            raise ApiError(f"rejected: {exc}", HTTPStatus.CONFLICT)
        return self.state()

    # -------------------------------------------------------------- voters
    def register(self, body: dict) -> dict:
        el = self._require_election()
        entry = el.by_code.get(_digest(_normalise_code(body.get("code"))))
        if entry is None:
            raise ApiError("unknown registration code", HTTPStatus.FORBIDDEN)
        if entry["credential_id"]:
            raise ApiError("this registration code has already been used", HTTPStatus.CONFLICT)
        try:
            key = RSAPublicKey.from_dict(body["voter_public_key"])
        except (KeyError, TypeError, ValueError):
            raise ApiError("voter_public_key must be {n, e} in hex")
        if key.n.bit_length() < MIN_VOTER_KEY_BITS or key.e != 65537:
            raise ApiError(f"voter key must be at least {MIN_VOTER_KEY_BITS}-bit RSA with e = 65537")
        credential = el.authority.issue_credential(el.params.election_id, key)
        try:
            entry_on_board = el.service.register(credential)
        except Rejected as exc:
            raise ApiError(f"rejected: {exc}", HTTPStatus.CONFLICT)
        entry["credential_id"] = credential["credential_id"]
        return {"name": entry["name"], "credential": credential, "seq": entry_on_board["seq"]}

    def vote(self, body: dict) -> dict:
        signed = body.get("ballot")
        t0 = time.perf_counter()
        with self.lock:
            el = self._require_election()
            try:
                voter_key = el.service.precheck(signed if isinstance(signed, dict) else {})
            except Rejected as exc:
                raise ApiError(f"rejected: {exc}", HTTPStatus.CONFLICT)
            params = el.params_dict
        try:   # the expensive part, outside the lock and (with a pool) on another core
            if self.pool:
                self.pool.submit(check_ballot, params, voter_key, signed).result()
            else:
                check_ballot(params, voter_key, signed)
        except Rejected as exc:
            raise ApiError(f"rejected: {exc}", HTTPStatus.CONFLICT)
        except (KeyError, TypeError, ValueError) as exc:
            raise ApiError(f"rejected: malformed ballot ({exc})", HTTPStatus.CONFLICT)
        with self.lock:
            if self.election is not el:
                raise ApiError("the election changed while this ballot was being checked", HTTPStatus.CONFLICT)
            try:
                result = el.service.commit(signed)
            except Rejected as exc:
                raise ApiError(f"rejected: {exc}", HTTPStatus.CONFLICT)
        return {**result, "seconds": round(time.perf_counter() - t0, 2)}

    def audit(self, body: dict) -> dict:
        """Benaloh challenge, checked by different code than the browser that encrypted it."""
        el = self._require_election()
        p = el.params
        pk = p.paillier_public_key
        ballot, choice, randomness = body.get("body"), body.get("choice"), body.get("randomness")
        if not isinstance(ballot, dict) or not isinstance(choice, int) or not 0 <= choice < p.num_candidates \
                or not isinstance(randomness, list) or len(randomness) != p.num_candidates:
            raise ApiError("send {body, choice, randomness[]} for the spoiled ballot")
        try:
            cts = [hex_to_int(c) for c in ballot["ciphertexts"]]
            rs = [hex_to_int(r) for r in randomness]
            opens = [pk.encrypt(1 if i == choice else 0, r)[0] == c for i, (c, r) in enumerate(zip(cts, rs))]
        except (KeyError, TypeError, ValueError) as exc:
            raise ApiError(f"malformed audit: {exc}")
        try:
            verify_ballot_body(pk, p.election_id, p.num_candidates, ballot)
            proofs = "valid"
        except InvalidBallot as exc:
            proofs = str(exc)
        return {"ok": all(opens) and len(opens) == p.num_candidates, "opens": opens, "proofs": proofs,
                "candidate": p.candidates[choice]}

    # -------------------------------------------------------------- trustees
    def trustee_partial(self, body: dict) -> dict:
        el = self._require_election()
        j = _int(body.get("trustee"), "trustee")
        if not 0 <= j < el.params.trustees:
            raise ApiError("no such trustee")
        token = body.get("token")
        if not isinstance(token, str) or not hmac.compare_digest(_digest(token), el.trustee_digests[j]):
            raise ApiError("wrong trustee token", HTTPStatus.FORBIDDEN)
        if el.phase != "closed":
            raise ApiError("partial decryptions are accepted only after the polls close and before the result",
                           HTTPStatus.CONFLICT)
        partials = body.get("partials")
        if not isinstance(partials, list) or len(partials) != el.params.num_candidates:
            raise ApiError("send one partial per candidate")
        try:
            [hex_to_int(x) for x in partials]
        except (TypeError, ValueError):
            raise ApiError("partials must be hex integers")
        el.partials[j] = partials
        if len(el.partials) < el.params.trustees:
            return {"published": False, **self.state()}
        ordered = [el.partials[i] for i in range(el.params.trustees)]
        try:
            el.results = el.service.publish_results(ordered)
        except Rejected as exc:
            el.partials.clear()
            raise ApiError(f"{exc}. All trustees must submit again.", HTTPStatus.CONFLICT)
        return {"published": True, **self.state()}

    # -------------------------------------------------------------- public checks
    def verify_snapshot(self) -> list:
        """Under the lock: copy the finished board. The (slow) verification then runs outside it."""
        el = self._require_election()
        if el.results is None:
            raise ApiError("the verifier checks a finished election: tally it first", HTTPStatus.CONFLICT)
        return el.board.entries()

    def report(self, entries) -> dict:
        """Verify outside the lock, in the process pool; one cached report per board head."""
        head = entries[-1]["entry_hash"]
        with self.cache_lock:
            if head in self.reports:
                return self.reports[head]
        report = _report(entries, self.pool)
        with self.cache_lock:
            self.reports[head] = report
        return report

    def find_receipt(self, body: dict) -> dict:
        el = self._require_election()
        receipt = str(body.get("receipt") or "").strip().lower()
        if not receipt:
            raise ApiError("enter a receipt")
        seq = el.service.find_receipt(receipt)
        if seq is None:
            return {"found": False}
        entry = el.board.entry(seq)
        return {"found": True, "seq": seq, "entry_hash": entry["entry_hash"], "board_head": el.board.head}

    def stored(self) -> list:
        return list_boards(self.db) if self.db else []

    def stored_entries(self, board_id: str) -> list:
        entries = load_sqlite_entries(self.db, board_id) if self.db else []
        if not entries:
            raise ApiError("no stored election with that id", HTTPStatus.NOT_FOUND)
        return entries

    def stored_snapshot(self, board_id: str) -> list:
        entries = self.stored_entries(board_id)
        if not any(e["kind"] == "result" for e in entries):
            raise ApiError("that election was never tallied, so there is nothing to verify", HTTPStatus.CONFLICT)
        return entries

    # -------------------------------------------------------------- helpers
    def _require_election(self) -> HostedElection:
        if self.election is None:
            raise ApiError("no election yet", HTTPStatus.CONFLICT)
        return self.election

    def _require_admin(self, token) -> HostedElection:
        el = self._require_election()
        if not el.is_admin(token):
            raise ApiError("admin token required", HTTPStatus.FORBIDDEN)
        return el


def _report(entries, executor=None) -> dict:
    report = verify_election(entries, executor)
    return {"ok": report.ok, "results": report.results,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in report.checks]}


def _jsonl(entries) -> bytes:
    return "".join(json.dumps(e, sort_keys=True) + "\n" for e in entries).encode()


def _int(value, name) -> int:
    if isinstance(value, bool):
        raise ApiError(f"{name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ApiError(f"{name} must be an integer")


class RateLimiter:
    """Token bucket per client IP: `rate` requests per second, bursts up to `burst`."""

    def __init__(self, rate: float, burst: int):
        self.rate, self.burst = rate, burst
        self.buckets = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.rate <= 0:
            return True
        now = time.monotonic()
        with self.lock:
            tokens, last = self.buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self.buckets[key] = (tokens, now)
                return False
            self.buckets[key] = (tokens - 1, now)
            if len(self.buckets) > 10000:   # forget idle clients
                self.buckets = {k: v for k, v in self.buckets.items() if now - v[1] < 60}
            return True


class Handler(SimpleHTTPRequestHandler):
    host = None      # ElectionHost, set by make_server
    limiter = None   # RateLimiter
    tls = False
    proxy = False    # behind a TLS-terminating reverse proxy (Fly, Render, nginx): trust X-Forwarded-*
    proxy_hops = 1   # how many trusted proxies append to X-Forwarded-For

    def client_ip(self) -> str:
        """The client's IP for rate limiting. The leftmost X-Forwarded-For entry is whatever the client
        sent, so it is never trusted: each trusted proxy appends the address it saw, and the entry
        `proxy_hops` from the right is the last one written by a proxy we trust."""
        if self.proxy:
            fly = self.headers.get("Fly-Client-IP", "").strip()   # set by Fly's edge, not the client
            if fly:
                return fly
            hops = [h.strip() for h in self.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
            if len(hops) >= self.proxy_hops:
                return hops[-self.proxy_hops]
        return self.client_address[0]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, fmt, *args):
        if not self.path.startswith(("/api/state", "/api/board?")):
            super().log_message(fmt, *args)

    def end_headers(self):
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        if self.tls or (self.proxy and self.headers.get("X-Forwarded-Proto") == "https"):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        super().end_headers()

    def do_GET(self):
        path, _, query = self.path.partition("?")
        h = self.host
        if path == "/api/board":
            since = 0
            for part in query.split("&"):
                if part.startswith("since="):
                    since = max(0, _safe_int(part[6:]))
            return self._call(lambda: h.board(since))
        if path == "/api/board.jsonl":
            with h.lock:
                data = _jsonl(h.board())
            return self._download(data, "board.jsonl")
        routes = {
            "/api/state": h.state,
            "/api/elections": h.stored,
            "/api/admin/roll": lambda: h.admin_roll(self.headers.get("X-Admin-Token")),
        }
        if path == "/api/verify":
            return self._verify(h.verify_snapshot)
        if path in routes:
            return self._call(routes[path])
        parts = path.strip("/").split("/")   # api / elections / <board_id> / <action>
        if len(parts) == 4 and parts[:2] == ["api", "elections"]:
            board_id, action = parts[2], parts[3]
            if action == "verify":
                return self._verify(lambda: h.stored_snapshot(board_id))
            if action == "board.jsonl":
                try:
                    with h.lock:
                        data = _jsonl(h.stored_entries(board_id))
                except ApiError as exc:
                    return self._json(exc.status, {"error": str(exc)})
                return self._download(data, f"board-{board_id}.jsonl")
        if path.startswith("/api/"):
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        if path == "/favicon.ico":   # pages carry an inline SVG icon; browsers still ask for this
            return self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
        return super().do_GET()

    def do_POST(self):
        h = self.host
        routes = {
            "/api/election": lambda b: h.create(b, self.headers.get("X-Organizer-Key")),
            "/api/close": lambda _b: h.close(self.headers.get("X-Admin-Token")),
            "/api/register": h.register,
            "/api/audit": h.audit,
            "/api/trustee/partial": h.trustee_partial,
            "/api/receipt": h.find_receipt,
        }
        path = self.path.split("?", 1)[0]
        if path not in routes and path != "/api/vote":
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        if not self.limiter.allow(self.client_ip()):
            return self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "too many requests: slow down"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request too large"})
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
        if path == "/api/vote":   # takes the lock itself, only around the cheap parts
            try:
                return self._json(HTTPStatus.OK, h.vote(body))
            except ApiError as exc:
                return self._json(exc.status, {"error": str(exc)})
        self._call(lambda: routes[path](body))

    def _verify(self, snapshot):
        try:
            with self.host.lock:
                entries = snapshot()
            result = self.host.report(entries)
        except ApiError as exc:
            return self._json(exc.status, {"error": str(exc)})
        self._json(HTTPStatus.OK, result)

    def _call(self, fn):
        try:
            with self.host.lock:
                result = fn()
        except ApiError as exc:
            return self._json(exc.status, {"error": str(exc)})
        self._json(HTTPStatus.OK, result)

    def _download(self, data, filename):
        self._send(HTTPStatus.OK, data, "application/x-ndjson",
                   {"Content-Disposition": f'attachment; filename="{filename}"'})

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


def _safe_int(s) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


def make_server(host="127.0.0.1", port=8000, db_path=None, workers=0, rate=20.0, burst=60,
                certfile=None, keyfile=None, proxy=False, proxy_hops=1,
                organizer_key=None) -> ThreadingHTTPServer:
    """db_path: SQLite file for the boards (None = memory). workers: processes that check ballots
    (0 = check in the request thread). rate/burst: POST limit per client IP (rate 0 = off).
    certfile/keyfile: serve HTTPS. proxy_hops: trusted proxies in front (with proxy=True).
    organizer_key: if set, POST /api/election needs it in X-Organizer-Key."""
    handler = type("BoundHandler", (Handler,), {
        "host": ElectionHost(db_path, workers, organizer_key),
        "limiter": RateLimiter(rate, burst),
        "tls": bool(certfile),
        "proxy": proxy,
        "proxy_hops": max(1, int(proxy_hops)),
    })
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        # handshake lazily, in each request's own thread, so a slow client cannot stall accept()
        server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    return server
