/* Crypto off the main thread: key generation, ballot encryption + proofs, signing, trustee partials.
 * Private keys and ballot randomness are only ever handled here and in this browser's storage. */
importScripts("gbcrypto.js");

const keyFromHex = (k) => Object.fromEntries(Object.entries(k).map(([name, v]) => [name, GB.fromHex(v)]));
const keyToHex = (k) => Object.fromEntries(Object.entries(k).map(([name, v]) => [name, GB.hex(v)]));

const ops = {
  keygen({ bits }) {
    const t0 = performance.now();
    const key = GB.rsaKeygen(bits);
    const pub = GB.rsaPublicDict(key);
    return { private_key: keyToHex(key), public_key: pub, credential_id: GB.fingerprint(pub), ms: performance.now() - t0 };
  },
  encrypt({ n, election_id, credential_id, num_candidates, choice }, progress) {
    const t0 = performance.now();
    const out = GB.encryptBallot(n, election_id, credential_id, num_candidates, choice, progress);
    return { ...out, fingerprint: GB.hashObj(out.body), ms: performance.now() - t0 };
  },
  sign({ private_key, body }) {
    const t0 = performance.now();
    const key = keyFromHex(private_key);
    const signed = { body, signature: GB.hex(GB.rsaSign(key, GB.ballotSigningBytes(body))) };
    return { signed, receipt: GB.ballotHash(signed), ms: performance.now() - t0 };
  },
  audit({ n, body, choice, randomness }) {
    return GB.auditBallot(n, body, choice, randomness);
  },
  trustee({ n, share, bodies, num_candidates }) {
    const t0 = performance.now();
    const totals = GB.aggregate(n, bodies, num_candidates);
    return { totals, partials: GB.partialDecrypt(n, share, totals), ms: performance.now() - t0 };
  },
};

self.onmessage = ({ data: { id, op, args } }) => {
  try {
    const result = ops[op](args, (progress) => self.postMessage({ id, progress }));
    self.postMessage({ id, result });
  } catch (err) {
    self.postMessage({ id, error: err.message || String(err) });
  }
};
