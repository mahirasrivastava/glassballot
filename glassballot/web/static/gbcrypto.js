/* Glass Ballot client-side cryptography: the browser half of the protocol.
 *
 * A line-by-line port of the Python package, so the server and the public
 * verifier accept what the browser produces:
 *   canonical JSON + SHA-256      glassballot/crypto/encoding.py
 *   Fiat-Shamir challenges        glassballot/crypto/fiat_shamir.py
 *   Paillier encrypt, OR-proof    glassballot/crypto/paillier.py, sigma.py
 *   sum proof                     glassballot/crypto/proofs.py
 *   one-hot ballot                glassballot/election/ballot.py
 *   RSA keygen + PKCS#1 v1.5      glassballot/crypto/rsa.py
 *   trustee partial decryption    glassballot/election/tally.py
 * Big integers are BigInt and travel as lowercase hex, exactly like Python.
 * Runs in a page, a Web Worker and Node (tests/js/ checks it against Python).
 */
(function (root) {
  "use strict";

  // ------------------------------------------------------------ SHA-256 (FIPS 180-4)
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function sha256(bytes) {
    const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const len = bytes.length;
    const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
    padded.set(bytes);
    padded[len] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, Math.floor(len / 0x20000000));
    view.setUint32(padded.length - 4, (len << 3) >>> 0);
    const w = new Uint32Array(64);
    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = w[i - 15], b = w[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const t1 = (hh + S1 + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) ov.setUint32(i * 4, h[i]);
    return out;
  }

  const utf8 = (s) => new TextEncoder().encode(s);
  const toHexBytes = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const sha256Hex = (bytes) => toHexBytes(sha256(bytes));

  // ------------------------------------------------------------ canonical JSON (= encoding.py)
  // json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False). Only ints, never floats.
  function canonical(x) {
    if (x === null || typeof x === "boolean") return JSON.stringify(x);
    if (typeof x === "number") {
      if (!Number.isSafeInteger(x)) throw new Error("canonical JSON carries integers only");
      return String(x);
    }
    if (typeof x === "string") return JSON.stringify(x);
    if (Array.isArray(x)) return `[${x.map(canonical).join(",")}]`;
    if (typeof x === "object") {
      const keys = Object.keys(x).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(x[k])}`).join(",")}}`;
    }
    throw new Error(`cannot encode ${typeof x}`);
  }
  const canonicalBytes = (x) => utf8(canonical(x));
  const hashObj = (x) => sha256Hex(canonicalBytes(x));

  // ------------------------------------------------------------ big integers
  const hex = (x) => {
    if (typeof x !== "bigint" || x < 0n) throw new Error("only non-negative BigInts are encoded");
    return x.toString(16);
  };
  const fromHex = (s) => {
    if (typeof s !== "string" || !/^[0-9a-f]+$/.test(s)) throw new Error(`malformed hex integer: ${s}`);
    return BigInt(`0x${s}`);
  };
  const mod = (a, m) => ((a % m) + m) % m;
  const bitLength = (x) => (x === 0n ? 0 : x.toString(2).length);

  function modpow(base, exp, m) {
    if (exp < 0n) return modpow(modinv(base, m), -exp, m);
    if (m === 1n) return 0n;
    // 4-bit fixed window: ~25% fewer multiplications than plain square-and-multiply
    base = mod(base, m);
    const table = [1n, base];
    for (let i = 2; i < 16; i++) table.push((table[i - 1] * base) % m);
    const bits = exp.toString(16);
    let r = 1n;
    for (const ch of bits) {
      r = (r * r) % m; r = (r * r) % m; r = (r * r) % m; r = (r * r) % m;
      const d = parseInt(ch, 16);
      if (d) r = (r * table[d]) % m;
    }
    return r;
  }

  function gcd(a, b) {
    a = a < 0n ? -a : a; b = b < 0n ? -b : b;
    while (b) [a, b] = [b, a % b];
    return a;
  }

  function modinv(a, m) {
    let [r0, r1] = [mod(a, m), m];
    let [s0, s1] = [1n, 0n];
    while (r1) {
      const q = r0 / r1;
      [r0, r1] = [r1, r0 - q * r1];
      [s0, s1] = [s1, s0 - q * s1];
    }
    if (r0 !== 1n) throw new Error("not invertible");
    return mod(s0, m);
  }

  function randomBits(bits) {
    const bytes = new Uint8Array(Math.ceil(bits / 8));
    (root.crypto || require("crypto").webcrypto).getRandomValues(bytes);
    const extra = bytes.length * 8 - bits;
    if (extra) bytes[0] &= 0xff >> extra;
    return bytes.length ? BigInt(`0x${toHexBytes(bytes) || "0"}`) : 0n;
  }

  function randBelow(n) {           // uniform in [0, n)
    const bits = bitLength(n - 1n) || 1;
    for (;;) {
      const x = randomBits(bits);
      if (x < n) return x;
    }
  }

  function randomUnit(n) {          // uniform in Z_n^*
    for (;;) {
      const r = randBelow(n - 1n) + 1n;
      if (gcd(r, n) === 1n) return r;
    }
  }

  // ------------------------------------------------------------ primes (= numtheory.py)
  const SMALL_PRIMES = (() => {
    const out = [], flags = new Uint8Array(2001);
    for (let i = 2; i <= 2000; i++) {
      if (flags[i]) continue;
      out.push(BigInt(i));
      for (let j = i * i; j <= 2000; j += i) flags[j] = 1;
    }
    return out;
  })();

  function isProbablePrime(n, rounds = 32) {
    if (n < 2n) return false;
    for (const p of SMALL_PRIMES) {
      if (n === p) return true;
      if (n % p === 0n) return false;
    }
    let d = n - 1n, s = 0;
    while (!(d & 1n)) { d >>= 1n; s++; }
    for (let i = 0; i < rounds; i++) {
      const a = randBelow(n - 3n) + 2n;
      let x = modpow(a, d, n);
      if (x === 1n || x === n - 1n) continue;
      let witness = true;
      for (let j = 0; j < s - 1; j++) {
        x = (x * x) % n;
        if (x === n - 1n) { witness = false; break; }
      }
      if (witness) return false;
    }
    return true;
  }

  function randomPrime(bits) {      // exactly `bits` bits, top two set (so p*q has 2*bits bits)
    const top = (1n << BigInt(bits - 1)) | (1n << BigInt(bits - 2)) | 1n;
    for (;;) {
      const c = randomBits(bits) | top;
      if (isProbablePrime(c)) return c;
    }
  }

  // ------------------------------------------------------------ RSA (= rsa.py)
  const E = 65537n;
  const DIGEST_INFO = Uint8Array.from([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]);

  function rsaKeygen(bits = 2048) {
    const half = bits >> 1;
    for (;;) {
      const p = randomPrime(half), q = randomPrime(bits - half);
      if (p === q || gcd(E, p - 1n) !== 1n || gcd(E, q - 1n) !== 1n) continue;
      const n = p * q;
      if (bitLength(n) !== bits) continue;
      const lam = ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n);
      return { n, e: E, d: modinv(E, lam), p, q };
    }
  }

  const rsaPublicDict = (key) => ({ n: hex(key.n), e: hex(key.e) });
  const fingerprint = (pub) => hashObj(pub);          // credential_id

  function emsa(message, k) {
    const t = new Uint8Array(DIGEST_INFO.length + 32);
    t.set(DIGEST_INFO);
    t.set(sha256(message), DIGEST_INFO.length);
    if (k < t.length + 11) throw new Error("RSA modulus too short for SHA-256 PKCS#1 v1.5");
    const em = new Uint8Array(k).fill(0xff);
    em[0] = 0; em[1] = 1; em[k - t.length - 1] = 0;
    em.set(t, k - t.length);
    return BigInt(`0x${toHexBytes(em)}`);
  }

  function rsaSign(key, message) {
    const k = Math.ceil(bitLength(key.n) / 8);
    const em = emsa(message, k);
    const dp = key.d % (key.p - 1n), dq = key.d % (key.q - 1n), qInv = modinv(key.q, key.p);
    const m1 = modpow(em, dp, key.p), m2 = modpow(em, dq, key.q);
    const s = m2 + mod(qInv * (m1 - m2), key.p) * key.q;
    if (modpow(s, key.e, key.n) !== em) throw new Error("RSA signature self-check failed");
    return s;
  }

  function rsaVerify(pub, message, s) {
    if (s < 0n || s >= pub.n) return false;
    return modpow(s, pub.e, pub.n) === emsa(message, Math.ceil(bitLength(pub.n) / 8));
  }

  // ------------------------------------------------------------ Fiat-Shamir (= fiat_shamir.py)
  const CHALLENGE_MODULUS = 1n << 128n;
  const DOMAIN_BINARY = "glassballot/v1/ballot-choice-is-0-or-1";
  const DOMAIN_SUM = "glassballot/v1/ballot-sum-is-1";

  function challenge(domain, transcript) {
    const digest = sha256(canonicalBytes({ domain, transcript }));
    return BigInt(`0x${toHexBytes(digest.slice(0, 16))}`);
  }

  function transcript(n, context, elements) {
    const t = { n: hex(n), context };
    for (const [k, v] of Object.entries(elements)) t[k] = hex(v);
    return t;
  }

  // ------------------------------------------------------------ Paillier + proofs (= paillier.py, sigma.py, proofs.py)
  const gPow = (n, m) => mod(1n + mod(m, n) * n, n * n);

  function encrypt(n, m, r = randomUnit(n)) {
    const n2 = n * n;
    return { c: (gPow(n, m) * modpow(r, n, n2)) % n2, r };
  }

  function proveNthResidue(n, u, r, context, domain) {
    const n2 = n * n;
    if (modpow(r, n, n2) !== mod(u, n2)) throw new Error("witness r does not satisfy u = r^n mod n^2");
    const s = randomUnit(n);
    const a = modpow(s, n, n2);
    const e = challenge(domain, transcript(n, context, { u, a }));
    const z = (s * modpow(r, e, n)) % n;
    return { a: hex(a), z: hex(z) };
  }

  function proveBinary(n, c, m, r, context) {
    const n2 = n * n;
    if (m !== 0 && m !== 1) throw new Error("binary proof only for m in {0, 1}");
    const u = [c, (c * gPow(n, -1n)) % n2];
    const t = m, f = 1 - m;
    const a = [0n, 0n], e = [0n, 0n], z = [0n, 0n];
    e[f] = randBelow(CHALLENGE_MODULUS);                       // simulated branch
    z[f] = randomUnit(n);
    a[f] = (modpow(z[f], n, n2) * modpow(u[f], -e[f], n2)) % n2;
    const s = randomUnit(n);                                   // real branch
    a[t] = modpow(s, n, n2);
    const ch = challenge(DOMAIN_BINARY, transcript(n, context, { c, a0: a[0], a1: a[1] }));
    e[t] = mod(ch - e[f], CHALLENGE_MODULUS);
    z[t] = (s * modpow(r, e[t], n)) % n;
    return { a0: hex(a[0]), a1: hex(a[1]), e0: hex(e[0]), e1: hex(e[1]), z0: hex(z[0]), z1: hex(z[1]) };
  }

  function proveSum(n, ciphertexts, total, rProduct, context) {
    const n2 = n * n;
    let acc = 1n;
    for (const c of ciphertexts) acc = (acc * c) % n2;
    const u = (acc * gPow(n, -BigInt(total))) % n2;
    return proveNthResidue(n, u, rProduct, context, DOMAIN_SUM);
  }

  // ------------------------------------------------------------ ballot (= ballot.py)
  const choiceContext = (electionId, credentialId, index) => ({ election_id: electionId, credential_id: credentialId, candidate: index });
  const sumContext = (electionId, credentialId, ctsHex) => ({ election_id: electionId, credential_id: credentialId, ciphertexts_hash: hashObj(ctsHex) });

  /* Returns { body, randomness } - randomness (hex r_i) stays on the device; it is only
   * revealed if the voter audits (spoils) this ballot instead of casting it. */
  function encryptBallot(nHex, electionId, credentialId, numCandidates, choice, onStep = () => {}) {
    const n = fromHex(nHex);
    if (!(choice >= 0 && choice < numCandidates)) throw new Error("choice out of range");
    const cts = [], proofs = [], rs = [];
    let rProduct = 1n;
    for (let i = 0; i < numCandidates; i++) {
      const m = i === choice ? 1 : 0;
      onStep({ step: "encrypt", candidate: i });
      const { c, r } = encrypt(n, BigInt(m));
      onStep({ step: "prove", candidate: i, ciphertext: hex(c) });
      proofs.push(proveBinary(n, c, m, r, choiceContext(electionId, credentialId, i)));
      cts.push(c); rs.push(r);
      rProduct = (rProduct * r) % n;
    }
    const ctsHex = cts.map(hex);
    onStep({ step: "sum" });
    const body = {
      election_id: electionId,
      credential_id: credentialId,
      ciphertexts: ctsHex,
      choice_proofs: proofs,
      sum_proof: proveSum(n, cts, 1, rProduct, sumContext(electionId, credentialId, ctsHex)),
    };
    return { body, randomness: rs.map(hex) };
  }

  const ballotSigningBytes = (body) => canonicalBytes(body);
  const ballotHash = (signed) => hashObj(signed);

  /* Benaloh audit: does each ciphertext open to the claimed one-hot vote with the revealed r_i? */
  function auditBallot(nHex, body, choice, randomness) {
    const n = fromHex(nHex);
    return body.ciphertexts.map((cHex, i) => {
      const m = i === choice ? 1n : 0n;
      return encrypt(n, m, fromHex(randomness[i])).c === fromHex(cHex);
    });
  }

  // ------------------------------------------------------------ tally + trustee (= tally.py)
  function aggregate(nHex, bodies, numCandidates) {
    const n = fromHex(nHex), n2 = n * n;
    const totals = Array(numCandidates).fill(1n);
    for (const b of bodies) b.ciphertexts.forEach((c, i) => { totals[i] = (totals[i] * fromHex(c)) % n2; });
    return totals.map(hex);
  }

  function partialDecrypt(nHex, shareHex, totalsHex) {
    const n = fromHex(nHex), share = fromHex(shareHex);
    return totalsHex.map((t) => hex(modpow(fromHex(t) % n, share, n)));
  }

  const api = {
    sha256, sha256Hex, utf8, canonical, canonicalBytes, hashObj,
    hex, fromHex, modpow, modinv, gcd, bitLength, randBelow, randomUnit,
    isProbablePrime, randomPrime,
    rsaKeygen, rsaPublicDict, rsaSign, rsaVerify, fingerprint,
    challenge, gPow, encrypt, proveBinary, proveSum,
    encryptBallot, ballotSigningBytes, ballotHash, auditBallot,
    aggregate, partialDecrypt,
  };
  root.GB = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : globalThis);
