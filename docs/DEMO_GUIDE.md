# Glass Ballot: hands-on demo guide

A script for presenting the project live (about 15 minutes), plus where everything lives and answers to the
questions an examiner is likely to ask. Every command here has been run on this codebase.

---

## 0. Before you start (2 minutes, do it before the audience arrives)

```bash
cd glassballot
python3 -m unittest discover -s tests -t .      # expect: OK (55 tests)
python3 scripts/serve.py                        # http://127.0.0.1:8000
```

Open three things:

1. **Browser tab A:** `http://127.0.0.1:8000/learn.html`, the animated explainer.
2. **Browser tab B:** `http://127.0.0.1:8000`, the app. Open DevTools (⌥⌘I) on the **Network** tab.
3. **A terminal** in the project folder for the attack demo and the verifier.

If an old election is showing, click **New election** at the top right.

> Tip: use the 2048-bit key size for the real demo (key ceremony about 3–10 s). Use 1024-bit if you are short on time.

---

## 1. The idea, in 60 seconds (tab A, section 1)

Press **▶ Play all**. While it runs, say:

- "There are six roles: voter devices, the election authority, the server, the bulletin board, the trustees and any public verifier."
- "Red packets are secrets and teal ones are public. Notice the vote itself never travels. Only an encrypted ballot does."
- "The server is **not trusted**. It never sees a vote and holds no decryption key. Everything it does is posted to the board, and anyone can re-check it."

Scroll to the **trust grid** under the diagram: it is a one-line summary of what each party knows.

---

## 2. Key ceremony (tab B → setup form)

Fill in: title, 3 candidates, **5 voters**, **3 trustees**, **2048-bit**. On the hosted site, also enter the **organizer key**
(Render dashboard → the service → Environment → `GLASSBALLOT_ORGANIZER_KEY`). Click **Run the key ceremony**.

If asked "can't anyone just start an election?": not on the hosted server. `POST /api/election` needs the organizer key,
the server keeps only its SHA-256 hash and compares it in constant time. Locally it is off, so the demo needs no setup.

What happens (`glassballot/web/server.py` `HostedElection.__init__` → `election/tally.py` `key_ceremony`):

| Step | Code |
|---|---|
| Paillier key n = p·q (2048 bits), g = n + 1 | `crypto/paillier.py` `generate_keypair` |
| e′ = n⁻¹ mod λ split into 3 additive shares, then p, q, λ deleted | `election/tally.py` `split_key` |
| Authority RSA-2048 signing key | `election/authority.py` |
| 5 one-time registration codes (the server stores only SHA-256 hashes) | `web/server.py` `_new_code`, `by_code` |
| Admin token and 3 trustee tokens (only hashes kept) | `web/server.py` |
| Entry #0 on the board: the public keys and candidates | `election/service.py` `create_election` |

The **handover dialog** appears: "These secrets were shown once." Explain that the server now *cannot decrypt*, because it no longer has the key in any form.

**Show the public keys:** open the **Bulletin board** tab and expand block **#0**. You will see `paillier_public_key.n`, `authority_public_key.{n,e}` and `trustees: 3`.
On the explainer page, section **2 · Keys and who holds them** shows the same values, labelled.

---

## 3. Registration: who may vote (Authority tab → Voter booth)

1. **Authority** tab: five codes, all *unused*. Say: "In real life each code is posted to one eligible voter."
2. Click **Use on this device** for voter-1. The busy dialog shows the three steps:
   - the browser generates a **2048-bit RSA key pair** (`static/worker.js` → `gbcrypto.js` `rsaKeygen`)
   - it sends the code and the **public** key (`POST /api/register`); the authority signs a credential
   - the browser **checks the authority's signature** before trusting it (`app.js` `registerDevice`)
3. Click **Register every remaining voter on this device** to register the rest.

**Prove the private key stayed on the device:** DevTools → **Application → Local Storage** → key `gb.e.<election id>` → `devices[0].private_key`.
Then DevTools → **Network** → the `register` request: it contains only `voter_public_key {n, e}` and the code.

**Show a signature:** the board's **credential** entries carry `signature`. On the explainer, section 5 shows
"✓ Live: the authority's 2048-bit signature on credential #1 … verifies", computed in the browser right then.

---

## 4. Voting, and auditing the voting device (Voter booth)

1. Select **voter-1** and pick a candidate. Click **Encrypt my ballot**.
   The sealed-ballot card fills in as each ciphertext is made: one ciphertext per candidate, each "proved 0 or 1".
   Point at the **ballot fingerprint**: "the device has now committed to this exact ballot."
2. Click **Audit instead (spoil)**. The device reveals each rᵢ. **This browser** and the **server's independent Python code**
   both re-encrypt the claimed choice, and every row says *opens*. Say: "This is the Benaloh challenge. A device that cheats
   can't know whether I'll cast or audit, so it gets caught. This audited ballot is spoiled and never counted."
3. Click **Encrypt a fresh ballot**, then **Encrypt my ballot** again and **Sign & cast**.
4. The receipt card shows: 3 ciphertexts, the sum proof, the signature, "The receipt this device computed matches the server's", and the block number.
5. DevTools → **Network** → `vote` → **Payload**: only `ciphertexts`, `choice_proofs`, `sum_proof` and `signature`. **No candidate name or number anywhere.**
6. Vote with 2–3 more devices, choosing different candidates. Leave one device not voting to show abstention.

**Try to cheat:** select a device that already voted. The booth is locked, and the warning says the server, database and verifier would all reject a second ballot.

---

## 5. Attacks (terminal)

```bash
python3 scripts/attack_demo.py          # 10/10 attacks caught
```

Walk through the output: 5 rejected by the service (stuffing, double vote, copied ballot and forged signature at cast time, plus a bad trustee partial at tally time),
1 secrecy attack (2 of 3 trustees collude: "their partials open nothing"), and 4 caught later by the public verifier.

**The database refuses edits too:**

```bash
sqlite3 out/glassballot.db "UPDATE board_entries SET payload = '{}' WHERE seq = 1"
# Error: stepping, bulletin board is append-only (19)
```

---

## 6. Close the polls, then the trustees (Authority → Trustees)

1. **Authority** tab → **Close polls** (click twice: the button asks you to confirm).
2. **Trustees** tab: three cards. Click **Decrypt my share** for **trustee 1 and trustee 2 only**.
   Go to **Results & audit**: "2 of 3 trustees have submitted … The totals open only when all of them have." Nothing is revealed.
3. Click trustee 3. The totals are opened and published.

Explain with the card text: each trustee device recomputes Tᵢ = Π cᵢ **from the public board**, computes Pⱼ = (T mod n)^sⱼ mod n,
and sends only Pⱼ. The server multiplies the partials into R and checks gᵐ·Rⁿ = T (`election/tally.py` `combine`, `check_opening`).

For the maths, use explainer section 7: **Decrypt with all 3** opens the toy total, and **Try with only 2** shows "nothing opens".

---

## 7. Verify everything (Results & audit, then terminal)

1. **Run the verifier**. Eight checks appear one by one, then **Election verified**.
   The explainer's section 8 lists which attack each check catches.
2. Under each result: `T = …`, `R = Π partials = …`, `gᵐ·Rⁿ = T ⇒ m`.
3. **Check your receipt**: paste the receipt from the cast card → "Found at board block #n" → **Show block**.
4. The same check from the terminal, using only the stored board:

```bash
python3 scripts/verify_board.py out/glassballot.db           # newest election in the database
```

5. Tamper with a downloaded board and watch it fail. Download it with the **Download board.jsonl** button, or with curl:

```bash
curl -s http://127.0.0.1:8000/api/board.jsonl -o board.jsonl
python3 -c "import json; L=[json.loads(l) for l in open('board.jsonl')]; L[-1]['payload']['results'][0]['total'] += 1; open('tampered.jsonl','w').write(''.join(json.dumps(e)+'\n' for e in L))"
python3 scripts/verify_board.py tampered.jsonl               # [FAIL] hash chain ... ELECTION NOT VERIFIED
```

---

## 8. Scale (optional, terminal)

```bash
python3 scripts/serve.py --port 8765 --rate 0 --db "" &      # second server, rate limit off for one-IP load
python3 scripts/load_test.py --url http://127.0.0.1:8765 --voters 120
```

Expected on an 8-core laptop: about 8 ballots/s accepted at 2048 bits (about 28,000 per hour), the right totals, and *ELECTION VERIFIED*.
The talking points:
- ballot proofs are checked in a **process pool outside the lock**; only "not voted yet → append" is serialised
- the browser does the encryption (0.25 s per ballot), so the server only verifies
- verification is parallel and cached per board head

---

## What is where

| You see | UI | Code | API |
|---|---|---|---|
| Key ceremony | setup form | `web/server.py` `HostedElection`, `election/tally.py` `key_ceremony` | `POST /api/election` |
| Registration codes | Authority tab | `web/server.py` `register` | `GET /api/admin/roll`, `POST /api/register` |
| Device keys, encryption, proofs, signing | Voter booth | `static/gbcrypto.js`, `static/worker.js`, `static/app.js` | `POST /api/vote` |
| Ballot checks | (server) | `election/service.py` `precheck` / `check_ballot` / `commit` | |
| Benaloh audit | Voter booth → Audit | `gbcrypto.js` `auditBallot`, `web/server.py` `audit` | `POST /api/audit` |
| Close | Authority tab | `election/service.py` `close` | `POST /api/close` |
| Trustee partials | Trustees tab | `gbcrypto.js` `partialDecrypt`, `election/tally.py` `combine` | `POST /api/trustee/partial` |
| Verifier | Results & audit | `election/verifier.py`, `scripts/verify_board.py` | `GET /api/verify` |
| Board | Bulletin board tab | `election/bulletin_board.py`, `election/sqlite_board.py` | `GET /api/board?since=N` |
| Explainer | `learn.html` | `static/learn.js` | `GET /api/state`, `/api/board` |

---

## Likely questions, with short answers

**"Can the server see my vote?"** No. The browser encrypts it (`gbcrypto.js`) and the server receives only ciphertexts and proofs.
Show the DevTools Network payload, and the Wireshark capture below.

**"Can the server decrypt the ballots?"** No. It never holds the key. After the ceremony the decryption exponent exists only as
3 shares on 3 trustees' devices. Even 2 colluding trustees get nothing (attack demo line, and explainer section 7).

**"Then can all the trustees together decrypt my ballot?"** In principle yes. That is the trust assumption, as in Helios with threshold trustees.
Each trustee decrypts only totals it recomputed from the public board itself, so it refuses to touch a single ballot.

**"How do you know a ballot is 0 or 1 without decrypting it?"** With a zero-knowledge OR-proof (Cramer–Damgård–Schoenmakers): one branch is real and the other is simulated, and the verifier can't tell which.
The sum proof shows exactly one entry is 1. Explainer section 4 animates this with real 2048-bit ciphertexts.

**"Why Fiat–Shamir with the credential id inside the hash?"** It makes the proof non-interactive and binds it to *this* voter and *this* election.
A copied ballot fails ("ballot copied under another credential" in the attack demo).

**"How is the decryption checked without a proof?"** Revealing R makes the check direct: gᵐ·Rⁿ = T (mod n²). Since x ↦ xⁿ is a bijection
on ℤₙ*, only one (m, R) satisfies it. This is stronger than a zero-knowledge proof, because there is nothing to fake. R reveals nothing about any single ballot.

**"Why RSA signatures if the votes are Paillier?"** Different jobs. Paillier gives secrecy and addition, and RSA gives authenticity: the authority signs credentials,
and voters sign ballots. One credential gives one ballot, enforced three times (service, unique SQLite index, verifier).

**"What stops the server editing the database?"** Three layers. SQLite triggers block UPDATE and DELETE, and every entry hashes the previous one,
so any edit breaks the chain from that point on. The public verifier recomputes everything. Removing the triggers doesn't help, because the chain still breaks (demo step 7).

**"How do I know my ballot was counted?"** Your receipt is SHA-256 of your signed ballot. Your device computes it, you can look it up on the board,
the board is hash-chained, and the verified tally is the product of exactly the ballots on the board.

**"Can someone be coerced or sell their vote?"** This is not prevented: a voter could reveal rᵢ to prove their vote. That needs a different protocol
(JCJ/Civitas with fake credentials and mixnets). It is listed under limitations, as it is for Helios.

**"What if a trustee loses their share?"** With k-of-k, the tally can't be opened. The fix is t-of-k Shamir sharing (Shoup / Damgård–Jurik), which needs safe primes.
It is listed as future work.

**"Who generated the key? Couldn't they keep it?"** A single dealer process generates it and deletes it after splitting (`key_ceremony`). Removing this trust needs
distributed RSA-modulus generation (Boneh–Franklin), which is future work.

**"Is the JS crypto the same as the Python?"** Yes. `tests/test_js_crypto.py` runs `gbcrypto.js` under Node and checks that Python accepts its keys, signatures,
ballots, receipts and trustee partials byte for byte.

---

## Wireshark (showing what travels on the wire)

1. Start a capture on **Loopback: lo0**, with display filter `tcp.port == 8000 && http`.
2. Cast a ballot. Right-click `POST /api/vote` → **Follow → HTTP Stream**. You will see ciphertexts, proofs and the signature, **but no vote**.
3. Now run `python3 scripts/serve.py --tls` and capture with filter `tcp.port == 8443`. You will see only TLS 1.3 records.
4. To decrypt your own TLS traffic for the demo, start Chrome with a key log and point Wireshark at it
   (Preferences → Protocols → TLS → (Pre)-Master-Secret log filename):

```bash
SSLKEYLOGFILE=$HOME/tls-keys.log "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --user-data-dir=/tmp/gb-tls https://127.0.0.1:8443
```

The lesson: confidentiality of the vote does not depend on TLS (the ballot is end-to-end encrypted), but the admin and trustee tokens do, so use `--tls` for any non-local deployment.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| "This browser is not the election authority" | Use the browser that ran the key ceremony, or start a **New election** |
| Trustee card says "share not on this device" | Load the share file with **Load a trustee share file…** (downloaded from the Authority tab) |
| `too many requests` during a load test | Start the server with `--rate 0` |
| Self-signed certificate warning with `--tls` | Expected. Click through once (Advanced → Proceed), or pass `--cert` and `--key` |
| An open election disappeared after a restart | Keys live in memory, so start a new one. Old boards stay verifiable (setup page → **Past elections**) |
