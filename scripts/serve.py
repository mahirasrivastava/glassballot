#!/usr/bin/env python3
"""Serve the Glass Ballot web app and election API.

    python3 scripts/serve.py                 # http://127.0.0.1:8000, boards in out/glassballot.db
    python3 scripts/serve.py --tls           # https://127.0.0.1:8443 with a self-signed certificate
    python3 scripts/serve.py --db ""         # no database: boards live in memory only
    python3 scripts/serve.py --workers 8     # processes that check ballot proofs in parallel
    python3 scripts/serve.py --rate 0        # turn off the per-IP rate limit (load tests)
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from glassballot.web.server import make_server  # noqa: E402


def self_signed_cert(directory: Path, host: str):
    """Create (once) a self-signed certificate for `host` with the openssl CLI."""
    cert, key = directory / "cert.pem", directory / "key.pem"
    if cert.exists() and key.exists():
        return cert, key
    if not shutil.which("openssl"):
        sys.exit("--tls needs the openssl command (or pass --cert and --key)")
    directory.mkdir(parents=True, exist_ok=True)
    san = f"IP:{host}" if host.replace(".", "").isdigit() else f"DNS:{host}"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "30",
                    "-keyout", str(key), "-out", str(cert), "-subj", f"/CN={host}",
                    "-addext", f"subjectAltName={san},DNS:localhost"],
                   check=True, capture_output=True)
    key.chmod(0o600)
    return cert, key


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.environ["PORT"]) if os.environ.get("PORT") else None,
                    help="default $PORT, else 8000, or 8443 with --tls")
    ap.add_argument("--proxy", action="store_true",
                    help="behind a TLS-terminating proxy (Fly.io, Render, nginx): trust X-Forwarded-For/-Proto")
    ap.add_argument("--db", default="out/glassballot.db", help='SQLite file for bulletin boards ("" = memory only)')
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1,
                    help="processes that verify ballots in parallel (0 = in the request thread)")
    ap.add_argument("--rate", type=float, default=20.0, help="POST requests per second per client IP (0 = unlimited)")
    ap.add_argument("--burst", type=int, default=60, help="short bursts allowed above --rate")
    ap.add_argument("--tls", action="store_true", help="serve HTTPS (self-signed certificate in out/tls/)")
    ap.add_argument("--cert", help="PEM certificate for HTTPS (with --key)")
    ap.add_argument("--key", help="PEM private key for HTTPS")
    args = ap.parse_args()

    cert, key = args.cert, args.key
    if args.tls and not cert:
        cert, key = self_signed_cert(ROOT / "out" / "tls", args.host)
    scheme = "https" if cert else "http"
    port = args.port or (8443 if cert else 8000)

    server = make_server(args.host, port, args.db or None, workers=args.workers, rate=args.rate,
                         burst=args.burst, certfile=cert, keyfile=key, proxy=args.proxy)
    print(f"Glass Ballot on {scheme}://{args.host}:{port}  (Ctrl+C to stop)")
    print(f"  bulletin boards : {args.db or 'in memory only'}")
    print(f"  ballot checkers : {args.workers or 'request thread'} process(es)")
    if args.proxy:
        print("  reverse proxy   : client IP and HTTPS taken from X-Forwarded-* headers")
    print(f"  rate limit      : {f'{args.rate:g}/s per IP, burst {args.burst}' if args.rate > 0 else 'off'}")
    if cert:
        print(f"  certificate     : {cert} (self-signed: the browser will warn once)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if server.RequestHandlerClass.host.pool:
            server.RequestHandlerClass.host.pool.shutdown(cancel_futures=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
