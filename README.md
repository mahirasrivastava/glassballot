# Glass Ballot (Helios-Mini v2)

Verifiable encrypted voting. Ballots are encrypted **in the voter's browser** with Paillier and come with
zero-knowledge proofs. They are added up while still encrypted, and the totals are opened by **k trustees who each hold one
share of the key**. Every step is posted on a hash-chained bulletin board that anyone can re-check.
**Python 3 standard library only, no pip installs.** The browser side is plain JS (BigInt), and Node is needed only for the cross-check tests.

## Run it

```bash
python3 scripts/serve.py                         # web app on http://127.0.0.1:8000 (boards in out/glassballot.db)
python3 scripts/serve.py --tls                   # same on https://127.0.0.1:8443 (self-signed certificate)
python3 scripts/serve.py --organizer-key SECRET  # only holders of SECRET may start an election (or $GLASSBALLOT_ORGANIZER_KEY)
open http://127.0.0.1:8000/learn.html            # animated "How it works" with live values

python3 scripts/run_demo.py --voters 10          # whole election from the CLI, writes out/board.jsonl
python3 scripts/verify_board.py out/board.jsonl  # public verifier: board file only, no keys
python3 scripts/verify_board.py out/glassballot.db --list    # elections stored by the web app
python3 scripts/attack_demo.py                   # 10 attacks, each shown being caught
python3 scripts/load_test.py --voters 200        # many concurrent voters (start the server with --rate 0)

python3 -m unittest discover -s tests -t .       # 58 tests, ~7 s (JS cross-checks need node)
node tests/e2e/browser_flow.js http://127.0.0.1:8000 out/e2e   # whole election through the UI in headless Chrome
```

A hands-on demo script for presenting the project is in [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md).

## Who holds what

| Role | Holds (secret) | Never sees |
|---|---|---|
| Voter device (browser) | its RSA private key; the ballot randomness rᵢ | other voters' keys |
| Election authority | admin token; the RSA signing key for credentials | votes, the decryption key |
| Server | nothing secret about votes; only hashes of codes and tokens | votes (ballots arrive encrypted), voter keys, any key share |
| Trustee j | one additive share sⱼ of the decryption exponent | the other shares |
| Anyone | the public board | |

## Layout

```
glassballot/
  crypto/                       # no election knowledge; reusable
    numtheory.py                Miller-Rabin, prime generation, Z_n^* sampling
    encoding.py                 canonical JSON + SHA-256 (big ints as hex strings)
    paillier.py                 keygen, Enc, Dec, homomorphic add
    rsa.py                      RSASSA-PKCS1-v1_5 / SHA-256 sign + verify (CRT)
    fiat_shamir.py              128-bit challenges, domain-separation tags
    sigma.py                    n-th residuosity proof; 0-or-1 OR-proof (CDS)
    proofs.py                   sum-equals-1 proof (and a single-key decryption proof, unused by elections)
  election/                     # synopsis modules M1-M6
    params.py                   public election parameters (incl. number of trustees)
    authority.py         (M1)   credentials signed by the election authority
    voter.py, ballot.py  (M2,3) one-hot encrypted ballot + proofs + voter signature
    bulletin_board.py    (M4)   append-only, hash-chained JSONL board
    sqlite_board.py      (M4)   same board in SQLite: triggers block UPDATE/DELETE, unique indexes
    tally.py             (M5)   homomorphic aggregation; key split into k shares; threshold opening
    service.py                  accept/reject logic; ballot checks are pure so they run in a process pool
    verifier.py          (M6)   independent re-check of everything on the board (parallel)
  simulation.py                 wires a whole election together (CLI demo, tests, attacks)
  web/
    server.py                   stdlib HTTP API: roles, tokens, rate limit, CSP, TLS, process pool
    static/gbcrypto.js          browser crypto: a port of the Python, byte-compatible
    static/worker.js            Web Worker: keygen, encryption, proofs, signing, trustee partials
    static/app.js, index.html   the app (authority, voter booth, trustees, results, board)
    static/learn.*              animated architecture and cryptography explainer
scripts/                        serve, run_demo, verify_board, attack_demo, load_test
tests/                          crypto, election, threshold, SQLite, HTTP API, JS<->Python, e2e browser flow
docs/DEMO_GUIDE.md              presenter's guide
```

## The mathematics

**Paillier** (g = n + 1): Enc(m, r) = (1 + mn) · rⁿ mod n². Multiplying ciphertexts gives an encryption of
the sum, so a candidate's total is T = Π cᵢ, and individual ballots are never decrypted.

**Ballot** for k candidates: one ciphertext per candidate, cᵢ = Enc(mᵢ, rᵢ), exactly one of them 1.

| Proof | Statement | Witness |
|---|---|---|
| 0-or-1 OR-proof (per candidate) | cᵢ or cᵢ·g⁻¹ is an n-th residue | rᵢ |
| Sum proof (per ballot) | (Π cᵢ)·g⁻¹ = Rⁿ | R = Π rᵢ mod n |

Both use one Σ-protocol made non-interactive with Fiat–Shamir:
commit a = sⁿ, challenge e = H(domain, n, context, u, a), respond z = s·rᵉ mod n, verify zⁿ ≡ a·uᵉ (mod n²).
Every challenge hashes the election ID, credential ID and candidate index, so a copied ballot fails.

**Threshold decryption (k-of-k).** With λ = lcm(p−1, q−1) let e′ = n⁻¹ mod λ. For T = gᵐRⁿ,
(T mod n)^e′ = R. At the key ceremony e′ is split into additive shares s₁ + … + sₖ ≡ e′ (mod λ), and p, q are deleted.
Trustee j publishes Pⱼ = (T mod n)^sⱼ mod n, so R = Π Pⱼ. The result is checked publicly: **gᵐ · Rⁿ ≡ T (mod n²)**.
Because x ↦ xⁿ is a bijection on ℤₙ*, only the true (m, R) passes, so this is a direct check rather than a
proof that needs extra assumptions. Any k−1 shares are statistically independent of e′.

**Credentials:** each voter's browser generates an RSA-2048 key, and the authority signs (election ID, SHA-256(key), key) after a
one-time registration code checks out. Ballots are signed by the voter.

**Benaloh audit (cast as intended):** the device seals a ballot (fixing its fingerprint), then the voter either casts it or
audits it. An audit reveals every rᵢ, and both the browser and the server's Python re-encrypt the claimed choice.

## Security goals

| Goal | How |
|---|---|
| Confidentiality | encryption in the browser; only totals are decrypted; needs all k trustees |
| Integrity | hash chain, database triggers and unique indexes, public verifier |
| Authentication / eligibility | one-time codes (hashed), authority-signed credentials, signed ballots; an organizer key (stored hashed) guards starting an election on a public server |
| One voter, one vote | service, SQLite unique index, verifier |
| Ballot validity | 0-or-1 and sum ZK proofs bound to election and credential |
| Accountability | everything signed and public, per-trustee partials on the board |
| Universal / individual verifiability | `verify_board.py`; receipts plus the Benaloh audit |
| Availability | proof checks in a process pool outside the lock, per-IP rate limit (behind a proxy, keyed on the address the trusted proxy appended, never the client-supplied part of `X-Forwarded-For`), body cap, cached verification, incremental board reads |
| Transport | optional HTTPS (TLS ≥ 1.2, HSTS), strict CSP, nosniff, frame-deny, no referrer |

Measured on an 8-core laptop at 2048 bits: about 8 ballots/s accepted (about 28,000 per hour); 120 concurrent ballots verified by
the public verifier in 16 s. In the browser, a 2048-bit key takes about 0.25 s and a 3-candidate ballot with proofs about 0.25 s.

## Limitations

- **No coercion resistance** (as in Helios): a voter can prove their vote by revealing rᵢ. That needs a different protocol (JCJ/Civitas).
- **Trusted dealer:** one process generates and splits the key, then deletes it. Distributed RSA-modulus generation is future work.
- **k-of-k:** every trustee must take part. t-of-k (Shoup / Damgård–Jurik) needs safe primes and is future work.
- **Demo convenience:** one browser can play every role, so its localStorage then holds every secret. Use separate devices for real.
- Keys live in server memory, so an election still open when the server stops cannot be resumed (its board can still be verified).
- **Hosted deploys:** set an organizer key (`render.yaml` generates `GLASSBALLOT_ORGANIZER_KEY`; on Fly use `fly secrets set`), otherwise
  anyone who opens the site can replace the running election. Set `PROXY_HOPS` if more than one proxy appends to `X-Forwarded-For`.
- Next steps: CI.
