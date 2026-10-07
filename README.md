# Glass Ballot (Helios-Mini v2)

Verifiable encrypted voting: Paillier homomorphic tally, RSA credentials, and a
zero-knowledge audit trail anyone can check. **Pure Python 3 standard library: no pip installs.**

## Run it

```bash
python3 scripts/run_demo.py --voters 10          # full election, writes out/board.jsonl
python3 scripts/verify_board.py out/board.jsonl  # public verifier: board file only, no keys
python3 scripts/attack_demo.py                   # 8 attacks, each shown being caught
python3 -m unittest discover -s tests -t .       # 33 tests, ~4 s
python3 scripts/serve.py                         # web booth on http://127.0.0.1:8000
```

## Layout

```
glassballot/
  crypto/                       # no election knowledge; reusable
    numtheory.py                Miller-Rabin, prime generation, Z_n^* sampling
    encoding.py                 canonical JSON + SHA-256 (big ints as hex strings)
    paillier.py                 keygen, Enc, Dec, homomorphic add, randomness recovery
    rsa.py                      RSASSA-PKCS1-v1_5 / SHA-256 sign + verify (CRT)
    fiat_shamir.py              128-bit challenges, domain-separation tags
    sigma.py                    n-th residuosity proof; 0-or-1 OR-proof (CDS)
    proofs.py                   sum-equals-1 proof; proof of correct decryption
  election/                     # synopsis modules M1-M6
    params.py                   public election parameters
    authority.py         (M1)   credentials signed by the election authority
    voter.py, ballot.py  (M2,3) one-hot encrypted ballot + proofs + voter signature
    bulletin_board.py    (M4)   append-only, hash-chained JSONL board
    tally.py             (M5)   homomorphic aggregation; trustee decrypts once + proves
    service.py                  accept/reject logic (the future Flask API wraps this)
    verifier.py          (M6)   independent re-check of everything on the board
  simulation.py                 wires a whole election together
  web/
    server.py                   stdlib HTTP API around service.py (stand-in for Flask)
    static/                     voting booth, bulletin board viewer, tally + verifier UI
scripts/                        run_demo.py, verify_board.py, attack_demo.py, serve.py
tests/                          test_crypto.py, test_election.py
```

## The mathematics

**Paillier** (g = n + 1): Enc(m, r) = (1 + mn) · rⁿ mod n²; Dec(c) = L(c^λ mod n²) · μ mod n.
Product of ciphertexts = encryption of the sum, so a candidate's tally is Π cᵢ, decrypted once.

**Ballot** for k candidates: one ciphertext per candidate, cᵢ = Enc(mᵢ, rᵢ), one of them 1.

| Proof | Statement | Witness |
|---|---|---|
| 0-or-1 OR-proof (per candidate) | cᵢ or cᵢ·g⁻¹ is an n-th residue | rᵢ |
| Sum proof (per ballot) | (Π cᵢ)·g⁻¹ = Rⁿ | R = Π rᵢ mod n |
| Decryption proof (per candidate tally) | T·g⁻ᵐ = Rⁿ | R recovered by the trustee with the private key |

All three use one Σ-protocol made non-interactive with Fiat–Shamir:
commit a = sⁿ, challenge e = H(domain, n, context, u, a), respond z = s·rᵉ mod n, verify zⁿ ≡ a·uᵉ (mod n²).

The decryption proof is the Paillier analogue of Chaum–Pedersen (which needs ElGamal).
Every challenge hashes the election ID, credential ID and candidate index, so a copied ballot fails.

**Credentials:** each voter generates an RSA key; the authority signs (election ID, voter public key).
Ballots are signed by the voter. credential_id = SHA-256 of the voter's public key.

## Not built yet (next phases)

- Flask REST API around `service.py`, and a PostgreSQL board with an append-only trigger
- In-browser ballot encryption for the voting booth (must reproduce `encoding.py` exactly for hashes
  to match); today `serve.py` encrypts on the voter's behalf and keeps one election in memory
- Docker, CI, benchmarks

## Limitations

- Single trustee holds the Paillier key (threshold decryption is future work).
- No coercion resistance; the ballot-to-credential link is public (as in Helios).
- Pure Python, so speed is limited: ~2.7 s per 3-candidate ballot at 2048-bit (encrypt + prove + server check).
