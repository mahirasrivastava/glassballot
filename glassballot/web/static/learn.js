"use strict";

/* "How it works" page. Every number is computed here, in the browser, with the same
 * gbcrypto.js the voting booth uses. Live values come from the election on this server. */

const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
const B = (x) => BigInt(x);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
document.documentElement.classList.add("anim");   // sections fade in on scroll only when this script runs

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "style") node.style.cssText = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children) if (c !== null && c !== undefined && c !== false) node.append(c);
  return node;
}
function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  node.append(...children);
  return node;
}
const mid = (h, a = 14, b = 6) => (h && h.length > a + b + 3 ? `${h.slice(0, a)}…${h.slice(-b)}` : h || "");
const bits = (hex) => Math.round((hex.length * 4) / 256) * 256;
const sub = (n) => String(n).replace(/\d/g, (d) => "₀₁₂₃₄₅₆₇₈₉"[d]);

// Click-to-expand long hex values.
function hexVal(hex, a = 16, b = 8) {
  const code = el("code", { class: "hexval", title: "click to expand" }, mid(hex, a, b));
  code.addEventListener("click", () => {
    const full = code.classList.toggle("full");
    code.textContent = full ? hex : mid(hex, a, b);
  });
  return code;
}

// Step lists that reveal line by line.
function calc(list, lines) {
  list.replaceChildren(...lines.map(([label, value, cls], i) => el("li", { class: cls || "", style: `--i:${i}` },
    el("span", { class: "calc-l" }, label), el("span", { class: "calc-v" }, value))));
}

// ---------------------------------------------------------------- live data
let live = null;   // { state, board }
async function loadLive() {
  try {
    const state = await (await fetch("/api/state")).json();
    if (state.phase === "none") return null;
    const board = await (await fetch("/api/board")).json();
    return { state, board };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- 1. architecture
const NODES = {
  voter: { x: 140, y: 270, label: "Voter device", sub: "browser · own RSA key" },
  authority: { x: 500, y: 72, label: "Election authority", sub: "admin token · signs credentials" },
  server: { x: 500, y: 270, label: "Server / API", sub: "checks, never decrypts" },
  board: { x: 500, y: 450, label: "Bulletin board", sub: "SQLite · hash chain" },
  trustees: { x: 860, y: 150, label: "Trustees × k", sub: "one key share each" },
  verifier: { x: 860, y: 400, label: "Anyone / verifier", sub: "re-checks the board" },
};
const EDGES = [["voter", "server"], ["authority", "server"], ["server", "board"], ["server", "trustees"],
  ["board", "verifier"], ["board", "trustees"], ["authority", "voter", "dash"], ["authority", "trustees", "dash"]];

const PHASES = [
  { name: "Key ceremony", steps: [
    ["authority", "authority", "public", "Generate the Paillier key (n = p·q) and the RSA signing key"],
    ["authority", "trustees", "secret", "Split e′ = n⁻¹ mod λ into k shares sⱼ, hand one to each trustee, delete p, q"],
    ["authority", "server", "public", "Publish the Paillier n, the authority's RSA (n, e) and the candidates"],
    ["server", "board", "public", "Entry #0: election parameters"],
    ["authority", "voter", "secret", "One-time registration code, out of band (post or e-mail)"],
  ] },
  { name: "Registration", steps: [
    ["voter", "voter", "secret", "Browser generates a 2048-bit RSA key pair; d never leaves"],
    ["voter", "server", "public", "Registration code + public key (n, e)"],
    ["server", "server", "public", "Code hash matches and is unused → authority signs the credential"],
    ["server", "board", "public", "Credential entry: SHA-256(key), the key, the authority's signature"],
    ["server", "voter", "public", "Credential back; the browser verifies the authority's signature"],
  ] },
  { name: "Voting", steps: [
    ["voter", "voter", "secret", "One-hot vote → cᵢ = gᵐⁱ·rᵢⁿ mod n², plus 0-or-1 proofs and a sum proof"],
    ["voter", "voter", "secret", "Optional audit: reveal rᵢ, check, then encrypt a fresh ballot"],
    ["voter", "server", "public", "Signed encrypted ballot (the vote itself never travels)"],
    ["server", "server", "public", "Check: on the roll, not yet voted, signature, every proof (process pool)"],
    ["server", "board", "public", "Ballot entry, chained to the previous hash"],
    ["server", "voter", "public", "Receipt = SHA-256(signed ballot); the device compares it with its own"],
  ] },
  { name: "Close & tally", steps: [
    ["authority", "server", "secret", "Close the polls (admin token)"],
    ["server", "board", "public", "Close entry: ballot count + head hash"],
    ["board", "trustees", "public", "Each trustee downloads the board"],
    ["trustees", "trustees", "secret", "Recompute Tᵢ = Π cᵢ, then Pⱼ = (Tᵢ mod n)^sⱼ mod n"],
  ] },
  { name: "Decryption", steps: [
    ["trustees", "server", "public", "Partials Pⱼ (+ trustee token); the share sⱼ stays put"],
    ["server", "server", "public", "R = Π Pⱼ; check gᵐ·Rⁿ = T (mod n²) → m"],
    ["server", "board", "public", "Result entry: T, m, R and every partial"],
  ] },
  { name: "Verification", steps: [
    ["board", "verifier", "public", "Download board.jsonl (no keys needed)"],
    ["verifier", "verifier", "public", "Re-check: chain, credentials, signatures, proofs, tally, opening"],
    ["verifier", "verifier", "public", "ELECTION VERIFIED, or the exact check that failed"],
  ] },
];

const arch = $("arch");
let archRun = 0;

function anchor(a, b) {
  // point on node a's box edge in the direction of b
  const A = NODES[a], Bn = NODES[b];
  const dx = Bn.x - A.x, dy = Bn.y - A.y;
  const w = 96, h = 40;
  const t = Math.min(w / Math.abs(dx || 1e-9), h / Math.abs(dy || 1e-9));
  return { x: A.x + dx * t, y: A.y + dy * t };
}

function drawArch() {
  arch.replaceChildren();
  const defs = svg("defs", {}, svg("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" },
    svg("path", { d: "M0,0 L10,5 L0,10 z", class: "arrow-head" })));
  arch.append(defs);
  for (const [a, b, style] of EDGES) {
    const p = anchor(a, b), q = anchor(b, a);
    arch.append(svg("line", { x1: p.x, y1: p.y, x2: q.x, y2: q.y, class: `edge${style ? ` ${style}` : ""}`, "data-edge": `${a}-${b}` }));
  }
  for (const [id, n] of Object.entries(NODES)) {
    arch.append(svg("g", { class: `node node-${id}`, "data-node": id, transform: `translate(${n.x - 96},${n.y - 38})` },
      svg("rect", { width: 192, height: 76, rx: 14 }),
      svg("text", { x: 96, y: 33, class: "node-label" }, n.label),
      svg("text", { x: 96, y: 53, class: "node-sub" }, n.sub)));
  }
  arch.append(svg("g", { id: "packets" }));
}

function tween(ms, fn) {
  return new Promise((resolve) => {
    if (reduced) { fn(1); return resolve(); }
    const t0 = performance.now();
    const frame = (now) => {
      const t = Math.min(1, (now - t0) / ms);
      fn(t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);
      if (t < 1) requestAnimationFrame(frame); else resolve();
    };
    requestAnimationFrame(frame);
  });
}

async function packet(from, to, kind, text, run) {
  const layer = $("packets");
  const nodeA = arch.querySelector(`[data-node=${from}]`), nodeB = arch.querySelector(`[data-node=${to}]`);
  nodeA.classList.add("active");
  if (from === to) {
    const n = NODES[from];
    const ring = svg("rect", { x: n.x - 96, y: n.y - 38, width: 192, height: 76, rx: 14, class: `pulse ${kind}` });
    layer.append(ring);
    await sleep(reduced ? 300 : 1300);
    ring.remove();
    nodeA.classList.remove("active");
    return run === archRun;
  }
  const p = anchor(from, to), q = anchor(to, from);
  const edge = arch.querySelector(`[data-edge=${from}-${to}], [data-edge=${to}-${from}]`);
  edge?.classList.add("hot", kind);
  const dot = svg("g", { class: `pk ${kind}` },
    svg("circle", { r: 9 }),
    svg("text", { y: 4, class: "pk-icon" }, kind === "secret" ? "🔒" : "✓"));
  layer.append(dot);
  await tween(1150, (t) => dot.setAttribute("transform", `translate(${p.x + (q.x - p.x) * t},${p.y + (q.y - p.y) * t})`));
  nodeB.classList.add("active");
  await sleep(reduced ? 100 : 250);
  dot.remove();
  edge?.classList.remove("hot", kind);
  nodeA.classList.remove("active");
  nodeB.classList.remove("active");
  return run === archRun;
}

function renderPhaseTabs(active) {
  $("phase-tabs").replaceChildren(...PHASES.map((ph, i) => el("button", {
    type: "button", class: i === active ? "on" : "", onclick: () => playPhases([i]),
  }, `${i + 1} ${ph.name}`)));
}

async function playPhases(which) {
  const run = ++archRun;
  for (const i of which) {
    renderPhaseTabs(i);
    const ph = PHASES[i];
    const items = ph.steps.map(([from, to, kind, text]) => el("li", { class: `${kind}` },
      el("span", { class: `tag ${kind}` }, kind), el("span", { class: "who" }, `${NODES[from].label}${from === to ? "" : ` → ${NODES[to].label}`}`), el("span", {}, text)));
    $("arch-log").replaceChildren(el("li", { class: "log-title" }, `Phase ${i + 1}: ${ph.name}`), ...items);
    for (const [s, [from, to, kind, text]] of ph.steps.entries()) {
      items.forEach((li, k) => li.classList.toggle("now", k === s));
      if (s > 0) items[s - 1].classList.add("done");
      if (!(await packet(from, to, kind, text, run))) return;
    }
    items.forEach((li) => { li.classList.remove("now"); li.classList.add("done"); });
    if (which.length > 1) await sleep(700);
    if (run !== archRun) return;
  }
}

drawArch();
renderPhaseTabs(-1);
$("arch-play").addEventListener("click", () => playPhases(PHASES.map((_, i) => i)));

// ---------------------------------------------------------------- 2. keys table
function renderKeys() {
  const rows = [];
  const e0 = live?.board.find((e) => e.kind === "election")?.payload;
  const cred = live?.board.find((e) => e.kind === "credential")?.payload;
  const k = e0?.trustees ?? 3;
  rows.push(["Election key", "Paillier, n = p·q", e0
    ? [el("span", {}, `n (${bits(e0.paillier_public_key.n)} bits) = `), hexVal(e0.paillier_public_key.n), el("span", {}, " · g = n + 1")]
    : "n (2048 bits), g = n + 1",
  `p, q and λ are destroyed after the ceremony. e′ = n⁻¹ mod λ lives only as ${k} additive shares, one per trustee.`]);
  rows.push(["Authority key", "RSA-2048, PKCS#1 v1.5 / SHA-256", e0
    ? [el("span", {}, "n = "), hexVal(e0.authority_public_key.n), el("span", {}, ` · e = ${parseInt(e0.authority_public_key.e, 16)}`)]
    : "n (2048 bits), e = 65537",
  "d: the election authority (server process memory). Signs credentials only."]);
  rows.push(["Voter key (one per device)", "RSA-2048, made in the browser", cred
    ? [el("span", {}, "credential_id = SHA-256(key) = "), hexVal(cred.credential_id), el("span", {}, " · n = "), hexVal(cred.voter_public_key.n)]
    : "(n, e) on the board inside the credential",
  "d: that voter's browser only (localStorage). Signs exactly one ballot."]);
  rows.push(["Ballot randomness rᵢ", "Paillier, one per ciphertext", "never published (the ciphertexts hide it)", "The voter's device. Revealed only if the voter audits (spoils) that ballot."]);
  rows.push(["Trustee shares sⱼ", "additive shares of e′", "partials Pⱼ = (T mod n)^sⱼ go on the board", "Each trustee's own device. The server keeps none."]);
  rows.push(["Admin token / trustee tokens", "random 192-bit secrets", "none", "Holder's browser. The server stores only their SHA-256 hashes."]);
  rows.push(["Registration codes", "12 characters from a 32-letter alphabet (60 bits)", "none", "Mailed to voters. The server checks them against SHA-256 hashes; each works once."]);
  $("keys-body").replaceChildren(...rows.map(([name, alg, pub, sec]) => el("tr", {},
    el("td", {}, el("strong", {}, name)), el("td", {}, alg),
    el("td", { class: "pubcell" }, ...(Array.isArray(pub) ? pub : [pub])), el("td", {}, sec))));
}

// ---------------------------------------------------------------- 3. toy Paillier
const TN = 77n, TN2 = TN * TN, TLAM = 30n, TMU = 18n;
const tEnc = (m, r) => (GB.gPow(TN, m) * GB.modpow(r, TN, TN2)) % TN2;
const tDec = (c) => (((GB.modpow(c, TLAM, TN2) - 1n) / TN) * TMU) % TN;
const randUnit = () => GB.randomUnit(TN);

function toyPaillier() {
  const m = B($("tp-m").value);
  const r = B(Math.max(1, Math.min(76, Number($("tp-r").value) || 1)));
  if (GB.gcd(r, TN) !== 1n) {
    calc($("tp-steps"), [["r must be coprime to n", `gcd(${r}, 77) = ${GB.gcd(r, TN)}. Pick another r.`, "bad"]]);
    return;
  }
  const gm = GB.gPow(TN, m), rn = GB.modpow(r, TN, TN2), c = (gm * rn) % TN2;
  const x = GB.modpow(c, TLAM, TN2);
  calc($("tp-steps"), [
    ["gᵐ = 1 + m·n", `1 + ${m}·77 = ${gm}`],
    ["rⁿ mod n²", `${r}⁷⁷ mod 5929 = ${rn}`],
    ["c = gᵐ·rⁿ mod n²", `${gm} · ${rn} mod 5929 = ${c}`, "hl"],
    ["decrypt: x = c^λ mod n²", `${c}³⁰ mod 5929 = ${x}`],
    ["m = L(x)·μ mod n", `(${x} − 1)/77 · 18 mod 77 = ${tDec(c)}`, "ok"],
  ]);
}
$("tp-m").addEventListener("change", toyPaillier);
$("tp-r").addEventListener("input", toyPaillier);
$("tp-rand").addEventListener("click", () => { $("tp-r").value = String(randUnit()); toyPaillier(); });

const toyBallots = [{ m: 1n }, { m: 0n }, { m: 1n }];
function renderToyBallots() {
  $("tp-ballots").replaceChildren(...toyBallots.map((b, i) => {
    b.r = b.r || randUnit();
    b.c = tEnc(b.m, b.r);
    return el("button", { type: "button", class: `tb${b.m ? " one" : ""}`, title: "click to flip the vote", onclick: () => {
      b.m = 1n - b.m; b.r = randUnit(); renderToyBallots(); $("tp-tally-steps").replaceChildren();
    } }, el("span", { class: "tb-m" }, `m${sub(i + 1)} = ${b.m}`), el("span", { class: "tb-c" }, `c${sub(i + 1)} = ${b.c}`));
  }));
}
$("tp-tally").addEventListener("click", () => {
  const T = toyBallots.reduce((a, b) => (a * b.c) % TN2, 1n);
  calc($("tp-tally-steps"), [
    ["T = c₁·c₂·c₃ mod n²", `${toyBallots.map((b) => b.c).join(" · ")} mod 5929 = ${T}`, "hl"],
    ["decrypt T once", `m = ${tDec(T)}`, "ok"],
    ["sum of the votes", `${toyBallots.map((b) => b.m).join(" + ")} = ${toyBallots.reduce((a, b) => a + b.m, 0n)} ✓`, "ok"],
  ]);
});

// ---------------------------------------------------------------- 4. ballot animation
let ballotN = null;
function ballotKey() {
  const e0 = live?.board.find((e) => e.kind === "election")?.payload;
  if (e0) return { n: e0.paillier_public_key.n, eid: e0.election_id, live: true };
  if (!ballotN) ballotN = GB.hex(GB.randomPrime(256) * GB.randomPrime(256));
  return { n: ballotN, eid: "learn-demo", live: false };
}
let ballotChoice = 1;
function candidates() {
  return live?.state.candidates || ["Alice", "Bob", "Carol"];
}
function renderBallotCands() {
  $("ba-cands").replaceChildren(...candidates().map((c, i) => el("button", {
    type: "button", class: i === ballotChoice ? "on" : "", onclick: () => { ballotChoice = i; renderBallotCands(); },
  }, c)));
}
let ballotRun = 0;
$("ba-play").addEventListener("click", async () => {
  const run = ++ballotRun;
  const { n, eid } = ballotKey();
  const N = GB.fromHex(n);
  const names = candidates();
  const stage = $("ba-stage");
  const rows = names.map((name, i) => {
    const m = i === ballotChoice ? 1 : 0;
    return { name, m, row: el("div", { class: "ba-row" },
      el("span", { class: "ba-name" }, name),
      el("span", { class: `ba-m${m ? " one" : ""}` }, String(m)),
      el("span", { class: "ba-arrow" }, "→"),
      el("code", { class: "ba-c" }, ""),
      el("span", { class: "ba-proof" }, "")) };
  });
  const sum = el("div", { class: "ba-sum" }, "");
  const sig = el("div", { class: "ba-sig" }, "");
  stage.replaceChildren(el("div", { class: "ba-head" }, el("span", {}, "candidate"), el("span", {}, "mᵢ"), el("span", {}), el("span", {}, `cᵢ = gᵐⁱ·rᵢⁿ mod n²  (n: ${bits(n)} bits)`), el("span", {}, "proof")),
    ...rows.map((r) => r.row), sum, sig);
  const cts = [];
  let rProd = 1n;
  for (const [i, r] of rows.entries()) {
    await sleep(reduced ? 0 : 450);
    if (run !== ballotRun) return;
    const { c, r: rnd } = GB.encrypt(N, B(r.m));
    const proof = GB.proveBinary(N, c, r.m, rnd, { election_id: eid, credential_id: "demo", candidate: i });
    cts.push(c); rProd = (rProd * rnd) % N;
    r.row.classList.add("enc");
    r.row.querySelector(".ba-m").textContent = "🔒";
    r.row.querySelector(".ba-c").textContent = mid(GB.hex(c), 18, 8);
    r.row.querySelector(".ba-c").title = GB.hex(c);
    r.row.querySelector(".ba-proof").replaceChildren(el("span", { class: "badge ok" }, "0 or 1"),
      el("span", { class: "muted tiny" }, ` e₀+e₁ = ${mid(GB.hex((GB.fromHex(proof.e0) + GB.fromHex(proof.e1)) % (1n << 128n)), 6, 4)}`));
  }
  await sleep(reduced ? 0 : 500);
  if (run !== ballotRun) return;
  const ctsHex = cts.map(GB.hex);
  GB.proveSum(N, cts, 1, rProd, { election_id: eid, credential_id: "demo", ciphertexts_hash: GB.hashObj(ctsHex) });
  sum.replaceChildren(el("span", { class: "badge ok" }, "sum proof"), ` Π cᵢ encrypts exactly 1: proved with R = Π rᵢ, which is never revealed`);
  sum.classList.add("in");
  await sleep(reduced ? 0 : 500);
  sig.replaceChildren(el("span", { class: "badge ok" }, "signed"), ` Body hashed (SHA-256 ${mid(GB.hashObj({ ciphertexts: ctsHex }), 10, 4)}) and signed with the device's RSA key, then sent`);
  sig.classList.add("in");
});

function renderLiveBallot() {
  const b = live?.board.find((e) => e.kind === "ballot");
  if (!b) return;
  $("live-ballot").hidden = false;
  $("lb-meta").textContent = `board entry #${b.seq}`;
  const text = JSON.stringify(b.payload, (k, v) => (typeof v === "string" && v.length > 48 ? `${v.slice(0, 22)}…${v.slice(-8)} ⟨${v.length * 4} bits⟩` : v), 2);
  $("lb-json").textContent = text;
}

// ---------------------------------------------------------------- 5. toy RSA
const RN = 3233n, RE = 17n, RD = 2753n;
let signedFor = null;
const toyHash = (msg) => GB.fromHex(GB.sha256Hex(GB.utf8(msg))) % RN;
function toyRsa() {
  const msg = $("tr-msg").value;
  if (signedFor === null) signedFor = msg;
  const hSigned = toyHash(signedFor), s = GB.modpow(hSigned, RD, RN);
  const h = toyHash(msg), back = GB.modpow(s, RE, RN);
  const ok = back === h;
  $("tr-pipe").replaceChildren(
    pipe("message", `"${msg}"`),
    pipe("SHA-256", mid(GB.sha256Hex(GB.utf8(msg)), 14, 6)),
    pipe("h = H mod n (toy)", String(h)),
    pipe(`signature s = h_signed^d mod n`, `${hSigned}²⁷⁵³ mod 3233 = ${s}`, "hl"),
    pipe("verify: s^e mod n", `${s}¹⁷ mod 3233 = ${back}`),
    pipe("equals h?", ok ? `${back} = ${h} ✓ valid` : `${back} ≠ ${h} ✕ rejected`, ok ? "ok" : "bad"),
  );
}
function pipe(label, value, cls = "") {
  return el("div", { class: `pipe ${cls}` }, el("span", { class: "pipe-l" }, label), el("span", { class: "pipe-v" }, value));
}
$("tr-msg").addEventListener("input", () => { signedFor = $("tr-msg").value; toyRsa(); });
// Change the message but keep the old signature, as an attacker would.
$("tr-tamper").addEventListener("click", () => {
  const msg = $("tr-msg").value;
  $("tr-msg").value = msg.includes("Bob") ? msg.replace("Bob", "Alice") : `${msg}!`;
  toyRsa();
});
$("tr-reset").addEventListener("click", () => { $("tr-msg").value = "ballot for Bob"; signedFor = null; toyRsa(); });

function liveSignatureCheck() {
  const e0 = live?.board.find((e) => e.kind === "election")?.payload;
  const cred = live?.board.find((e) => e.kind === "credential");
  if (!e0 || !cred) return;
  const p = cred.payload;
  const payload = { election_id: p.election_id, credential_id: p.credential_id, voter_public_key: p.voter_public_key };
  const t0 = performance.now();
  const ok = GB.rsaVerify({ n: GB.fromHex(e0.authority_public_key.n), e: GB.fromHex(e0.authority_public_key.e) }, GB.canonicalBytes(payload), GB.fromHex(p.signature));
  const ms = performance.now() - t0;
  $("toy-rsa").append(el("div", { class: `live-check ${ok ? "ok" : "bad"}` },
    el("strong", {}, ok ? "✓ Live: " : "✕ Live: "),
    `the authority's 2048-bit signature on credential #${cred.seq} of this server's board ${ok ? "verifies" : "does NOT verify"}. Checked in your browser just now (${ms.toFixed(1)} ms): SHA-256, PKCS#1 v1.5 padding, sᵉ mod n.`));
}

// ---------------------------------------------------------------- 6. hash chain
let chain = [];
function freshChain() {
  const payloads = [
    ["election", { title: "Demo", candidates: ["Alice", "Bob"] }],
    ["credential", { voter: "key-fingerprint-1" }],
    ["ballot", { ciphertexts: ["9f3a…", "41c0…"] }],
    ["ballot", { ciphertexts: ["07be…", "c2d9…"] }],
    ["close", { ballot_count: 2 }],
  ];
  let prev = "0".repeat(64);
  chain = payloads.map(([kind, payload], seq) => {
    const entry_hash = GB.hashObj({ seq, kind, payload, prev_hash: prev });
    const e = { seq, kind, payload, prev_hash: prev, entry_hash };
    prev = entry_hash;
    return e;
  });
  renderChain();
}
function renderChain() {
  let prevStored = "0".repeat(64);
  const blocks = chain.map((e, i) => {
    const computed = GB.hashObj({ seq: e.seq, kind: e.kind, payload: e.payload, prev_hash: e.prev_hash });
    const contentOk = computed === e.entry_hash;
    const linkOk = e.prev_hash === prevStored;
    prevStored = e.entry_hash;
    const field = el("input", { value: JSON.stringify(e.payload), spellcheck: "false", "aria-label": `payload of block ${i}` });
    field.addEventListener("change", () => {
      try { e.payload = JSON.parse(field.value); } catch { e.payload = field.value; }
      renderChain();
    });
    return el("div", { class: `cblock${contentOk ? "" : " bad-content"}${linkOk ? "" : " bad-link"}` },
      el("div", { class: "cb-head" }, el("span", { class: "seq" }, `#${i}`), el("span", { class: `kind kind-${e.kind}` }, e.kind)),
      el("label", { class: "cb-field" }, el("span", {}, "payload"), field),
      el("div", { class: "cb-hash" }, el("span", {}, "prev"), el("code", { class: linkOk ? "" : "badtxt" }, e.prev_hash.slice(0, 12))),
      el("div", { class: "cb-hash" }, el("span", {}, "hash"), el("code", {}, e.entry_hash.slice(0, 12))),
      el("div", { class: "cb-status" }, contentOk && linkOk ? "✓ intact" : !contentOk ? "✕ content ≠ hash" : "✕ prev link broken"),
      !contentOk ? el("button", { type: "button", class: "btn ghost small", onclick: () => { e.entry_hash = computed; renderChain(); } }, "Attacker: re-hash") : null);
  });
  const parts = [];
  blocks.forEach((b, i) => {
    if (i) parts.push(el("span", { class: `clink${chain[i].prev_hash === chain[i - 1].entry_hash ? "" : " broken"}` }, "⛓"));
    parts.push(b);
  });
  $("chain-demo").replaceChildren(...parts);
}
$("chain-reset").addEventListener("click", freshChain);

// ---------------------------------------------------------------- 7. threshold toy
const SHARES = [40n, 55n, 18n];             // 40 + 55 + 18 = 113 ≡ 23 = e′ (mod 30)
const TT_BALLOTS = [[1n, 13n], [0n, 23n], [1n, 29n]];   // r chosen so that no two trustees can open T by accident
function thresholdRun(use) {
  const T = TT_BALLOTS.reduce((a, [m, r]) => (a * tEnc(m, r)) % TN2, 1n);
  const P = SHARES.map((s) => GB.modpow(T % TN, s, TN));
  const R = use.reduce((a, j) => (a * P[j]) % TN, 1n);
  const u = (T * GB.modinv(GB.modpow(R, TN, TN2), TN2)) % TN2;
  const opens = (u - 1n) % TN === 0n;
  const lines = [
    ["three ballots (1, 0, 1)", `T = Π cᵢ mod n² = ${T}`],
    ...use.map((j) => [`trustee ${j + 1}: P${sub(j + 1)} = (T mod n)^s${sub(j + 1)} mod n`, `${T % TN}^${SHARES[j]} mod 77 = ${P[j]}`]),
    [`R = ${use.map((j) => `P${sub(j + 1)}`).join("·")} mod n`, String(R), "hl"],
    ["T · R⁻ⁿ mod n²", `${u}${opens ? ` = 1 + ${(u - 1n) / TN}·77` : " is not of the form 1 + m·n"}`],
  ];
  if (opens) lines.push(["opened", `m = ${(u - 1n) / TN} ✓ and anyone can check gᵐ·Rⁿ = T`, "ok"]);
  else lines.push(["nothing opens", `with ${use.length} of 3 shares, R is garbage and the total stays sealed`, "bad"]);
  calc($("tt-steps"), lines);
}
$("tt-shares").replaceChildren(...SHARES.map((s, j) => el("span", { class: "share-chip" }, `s${sub(j + 1)} = ${s}`)),
  el("span", { class: "muted small" }, "40 + 55 + 18 = 113 ≡ 23 (mod 30)"));
$("tt-run").addEventListener("click", () => thresholdRun([0, 1, 2]));
$("tt-two").addEventListener("click", () => thresholdRun([0, 1]));

function renderLiveResult() {
  const res = live?.board.find((e) => e.kind === "result")?.payload.results;
  const e0 = live?.board.find((e) => e.kind === "election")?.payload;
  if (!res || !e0) return;
  const n = GB.fromHex(e0.paillier_public_key.n), n2 = n * n;
  $("live-result").hidden = false;
  $("lr-meta").textContent = `${e0.trustees} trustees · ${bits(e0.paillier_public_key.n)}-bit n`;
  $("lr-body").replaceChildren(...res.map((r) => {
    const T = GB.fromHex(r.encrypted_total), R = GB.fromHex(r.randomness);
    const prod = r.partials.reduce((a, p) => (a * GB.fromHex(p)) % n, 1n);
    const check = (GB.gPow(n, B(r.total)) * GB.modpow(R, n, n2)) % n2 === T;
    return el("div", { class: "lr-row" },
      el("strong", {}, `${r.name}: ${r.total}`),
      el("div", { class: "lr-vals" },
        el("span", {}, "T = "), hexVal(r.encrypted_total, 12, 6),
        ...r.partials.flatMap((p, j) => [el("span", {}, ` · P${sub(j + 1)} = `), hexVal(p, 8, 4)]),
        el("span", {}, " · R = "), hexVal(r.randomness, 10, 4)),
      el("div", { class: "lr-checks" },
        el("span", { class: `badge ${prod === R ? "ok" : "bad"}` }, "R = Π Pⱼ"),
        el("span", { class: `badge ${check ? "ok" : "bad"}` }, `gᵐ·Rⁿ = T for m = ${r.total}`),
        el("span", { class: "muted small" }, "checked in your browser")));
  }));
}

// ---------------------------------------------------------------- 8. verifier checks
const VCHECKS = [
  ["hash chain", "any edited, inserted, deleted or reordered entry"],
  ["board structure", "a missing close entry, a second result, entries after the result"],
  ["voter roll", "fake voters: credentials not signed by the authority, or duplicates"],
  ["ballots", "forged signatures, invalid proofs (stuffing), unregistered credentials, second ballots"],
  ["close entry", "a server lying about how many ballots it accepted"],
  ["homomorphic tally", "ballots dropped from or added to the encrypted totals"],
  ["decryption proofs", "a wrong announced total, or partials that do not multiply to R"],
  ["totals consistent", "totals that do not add up to the number of ballots"],
];
$("vchecks").replaceChildren(...VCHECKS.map(([name, catches], i) => el("li", { style: `--i:${i}` },
  el("span", { class: "check-icon" }, "✓"), el("span", {}, el("strong", {}, name), el("span", { class: "check-detail" }, `catches ${catches}`)))));

// ---------------------------------------------------------------- page chrome
$("theme-btn").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("gb.theme", root.dataset.theme); } catch { /* no storage */ }
});

const io = new IntersectionObserver((entries) => {
  for (const e of entries) {
    if (e.isIntersecting) {
      e.target.classList.add("seen");
      const link = document.querySelector(`.toc a[href="#${e.target.id}"]`);
      if (link) {
        document.querySelectorAll(".toc a").forEach((a) => a.classList.remove("on"));
        link.classList.add("on");
      }
    }
  }
}, { rootMargin: "-30% 0px -60% 0px" });
document.querySelectorAll(".lsec").forEach((s) => io.observe(s));
const seenIo = new IntersectionObserver((entries) => entries.forEach((e) => e.isIntersecting && e.target.classList.add("seen")), { threshold: 0.08 });
document.querySelectorAll(".lsec").forEach((s) => seenIo.observe(s));

// ---------------------------------------------------------------- boot
(async () => {
  toyPaillier();
  renderToyBallots();
  toyRsa();
  freshChain();
  thresholdRun([0, 1, 2]);
  renderBallotCands();
  live = await loadLive();
  $("live-pill").textContent = live ? `live · election ${live.state.election_id}` : "sample values (no election yet)";
  $("live-pill").classList.toggle("on", Boolean(live));
  renderKeys();
  renderBallotCands();
  renderLiveBallot();
  liveSignatureCheck();
  renderLiveResult();
})();
