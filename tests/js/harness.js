// Runs gbcrypto.js under Node for tests/test_js_crypto.py: JSON request on stdin, JSON reply on stdout.
"use strict";
const path = require("path");
const GB = require(path.join(__dirname, "../../glassballot/web/static/gbcrypto.js"));

const ops = {
  hash: ({ objects }) => objects.map((o) => ({ canonical: GB.canonical(o), sha256: GB.hashObj(o) })),
  challenge: ({ domain, transcript }) => GB.hex(GB.challenge(domain, transcript)),
  rsa: ({ bits, message }) => {
    const key = GB.rsaKeygen(bits);
    const pub = GB.rsaPublicDict(key);
    return { public_key: pub, fingerprint: GB.fingerprint(pub), signature: GB.hex(GB.rsaSign(key, GB.utf8(message))) };
  },
  ballot: ({ n, election_id, num_candidates, choice, bits }) => {
    const key = GB.rsaKeygen(bits);
    const pub = GB.rsaPublicDict(key);
    const credentialId = GB.fingerprint(pub);
    const t0 = Date.now();
    const { body, randomness } = GB.encryptBallot(n, election_id, credentialId, num_candidates, choice);
    const signed = { body, signature: GB.hex(GB.rsaSign(key, GB.ballotSigningBytes(body))) };
    return {
      public_key: pub, signed, randomness, receipt: GB.ballotHash(signed), ms: Date.now() - t0,
      audit_true: GB.auditBallot(n, body, choice, randomness),
      audit_wrong: GB.auditBallot(n, body, (choice + 1) % num_candidates, randomness),
    };
  },
  partial: ({ n, share, totals }) => GB.partialDecrypt(n, share, totals),
  aggregate: ({ n, bodies, k }) => GB.aggregate(n, bodies, k),
};

let input = "";
process.stdin.on("data", (d) => { input += d; });
process.stdin.on("end", () => {
  const req = JSON.parse(input);
  process.stdout.write(JSON.stringify(ops[req.op](req)));
});
