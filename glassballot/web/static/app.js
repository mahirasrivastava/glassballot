"use strict";

/* Glass Ballot web client. Roles on one page, as separate "devices":
 *   authority  - holds the admin token; hands out registration codes; closes the polls
 *   voters     - each device generates its own RSA key; ballots are encrypted, proven and signed here
 *   trustees   - each holds one key share; decrypts only totals it recomputed from the board
 * Secrets live in this browser's localStorage, per election (see `wallet`). The server never gets them. */

const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
const TABS = ["authority", "booth", "trustees", "tally", "board"];
const VOTER_KEY_BITS = 2048;

let state = { phase: "none" };
let board = [];
let report = null;          // last verifier report for the current election
let adminRoll = null;       // /api/admin/roll, when this browser holds the admin token
let showSetup = false;
let boardFilter = "all";
let selectedDevice = null;  // credential_id
let sealed = null;          // encrypted, not yet cast: { credential_id, choice, body, randomness, fingerprint, ms }
let lastCast = null;        // { credential_id, receipt, seq, ... }
let tab = [location.hash.slice(1), store("tab")].find((t) => TABS.includes(t)) || "booth";

// ---------------------------------------------------------------- helpers
function store(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(`gb.${key}`);
    localStorage.setItem(`gb.${key}`, value);
  } catch { /* storage unavailable: preferences just don't persist */ }
  return null;
}

// Per-election secrets of the "devices" in this browser. Falls back to memory if storage is blocked.
const memoryWallets = {};
const wallet = {
  get(eid) {
    try {
      const raw = localStorage.getItem(`gb.e.${eid}`);
      if (raw) return JSON.parse(raw);
    } catch { /* fall through */ }
    return memoryWallets[eid] || { devices: [], shares: [], trusteeOut: {} };
  },
  update(eid, fn) {
    const w = this.get(eid);
    fn(w);
    memoryWallets[eid] = w;
    try { localStorage.setItem(`gb.e.${eid}`, JSON.stringify(w)); } catch { /* memory only */ }
    return w;
  },
};
const myWallet = () => wallet.get(state.election_id);

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

const short = (h, n = 10) => (h ? `${h.slice(0, n)}…` : "");
const mid = (h, a = 14, b = 6) => (h && h.length > a + b + 3 ? `${h.slice(0, a)}…${h.slice(-b)}` : h || "");
const byte = (hex, i) => parseInt(hex.slice(i * 2, i * 2 + 2) || "0", 16);
const hue = (hex, i = 0) => Math.round((byte(hex, i) / 256) * 360);
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const secs = (ms) => `${(ms / 1000).toFixed(2)}s`;
const sub = (n) => String(n).replace(/\d/g, (d) => "₀₁₂₃₄₅₆₇₈₉"[d]);

function fingerprint(hex, n = 6) {
  const strip = el("span", { class: "fp", title: hex, "aria-hidden": "true" });
  for (let i = 0; i < n; i++) strip.append(el("i", { style: `background:hsl(${hue(hex, i)} 62% 52%)` }));
  return strip;
}

function identicon(hex, size = 36) {
  const h = hue(hex, 31);
  const g = svg("svg", { viewBox: "0 0 5 5", width: size, height: size, class: "identicon", "aria-hidden": "true" });
  g.append(svg("rect", { width: 5, height: 5, rx: 1, fill: `hsl(${h} 45% 50% / 0.16)` }));
  for (let y = 0; y < 5; y++) {
    for (let x = 0; x < 3; x++) {
      if (byte(hex, y * 3 + x) % 2) continue;
      for (const cx of new Set([x, 4 - x])) g.append(svg("rect", { x: cx, y, width: 1, height: 1, fill: `hsl(${h} 58% 48%)` }));
    }
  }
  return g;
}

function initials(name) {
  return name.replace(/[^A-Za-z0-9 ]/g, " ").trim().split(/\s+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase() || "?";
}

function download(filename, obj) {
  const a = el("a", { href: URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" })), download: filename });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

// ---------------------------------------------------------------- api, worker, feedback
async function api(path, body, headers = {}) {
  const opts = body === undefined ? { headers } : {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}
const adminHeaders = () => ({ "X-Admin-Token": myWallet().admin_token || "" });

const worker = new Worker("worker.js");
const pending = new Map();
let nextJob = 0;
worker.onmessage = ({ data }) => {
  const job = pending.get(data.id);
  if (!job) return;
  if ("progress" in data) return job.onProgress?.(data.progress);
  pending.delete(data.id);
  if (data.error) job.reject(new Error(data.error));
  else job.resolve(data.result);
};
function work(op, args, onProgress) {
  return new Promise((resolve, reject) => {
    const id = ++nextJob;
    pending.set(id, { resolve, reject, onProgress });
    worker.postMessage({ id, op, args });
  });
}

let busyDepth = 0;
async function busy(title, lines, fn) {
  $("busy-title").textContent = title;
  $("busy-lines").replaceChildren(...lines.map((l) => el("li", {}, l)));
  $("busy").hidden = false;
  busyDepth++;
  const t0 = performance.now();
  const tick = setInterval(() => { $("busy-time").textContent = `${((performance.now() - t0) / 1000).toFixed(1)} s`; }, 100);
  try {
    return await fn((line) => $("busy-lines").append(el("li", { class: "now" }, line)));
  } catch (err) {
    toast(err.message, "error");
  } finally {
    clearInterval(tick);
    busyDepth--;
    $("busy-time").textContent = "0.0 s";
    $("busy").hidden = true;
  }
}

function toast(msg, kind = "ok") {
  const t = el("div", { class: `toast ${kind}`, role: kind === "error" ? "alert" : "status" },
    el("span", { class: "toast-icon" }, kind === "error" ? "!" : "✓"), msg);
  $("toasts").append(t);
  while ($("toasts").children.length > 3) $("toasts").firstElementChild.remove();
  setTimeout(() => t.classList.add("out"), kind === "error" ? 7000 : 3500);
  setTimeout(() => t.remove(), kind === "error" ? 7400 : 3900);
}

// ---------------------------------------------------------------- derived data
const electionEntry = () => board.find((e) => e.kind === "election");
const paillierN = () => electionEntry()?.payload.paillier_public_key.n;
const votedSet = () => new Set(board.filter((e) => e.kind === "ballot").map((e) => e.payload.body.credential_id));
const ballotOf = (cred) => board.findLast((e) => e.kind === "ballot" && e.payload.body.credential_id === cred);

function nameOf(cred) {
  const d = (myWallet().devices || []).find((x) => x.credential_id === cred);
  if (d) return { name: d.name, how: "this device" };
  const r = adminRoll?.find((x) => x.credential_id === cred);
  return r ? { name: r.name, how: "known to the authority" } : null;
}

// ---------------------------------------------------------------- refresh + render
async function refresh() {
  const s = await api("/api/state");
  if (s.election_id !== state.election_id) {
    board = []; report = null; sealed = null; lastCast = null; adminRoll = null; selectedDevice = null;
  }
  state = s;
  if (state.phase !== "none") {
    board = board.concat(await api(`/api/board?since=${board.length}`));
    adminRoll = myWallet().admin_token ? await api("/api/admin/roll", undefined, adminHeaders()).catch(() => null) : null;
  }
  if (state.phase !== "tallied") report = null;
  render();
  if (!$("setup").hidden) await refreshArchive();
}

// Light polling so other devices (tabs, browsers) see new registrations, ballots and partials.
async function poll() {
  if (document.hidden || busyDepth) return;
  try {
    const s = await api("/api/state");
    if (s.election_id !== state.election_id || s.board_length !== state.board_length || s.phase !== state.phase
        || JSON.stringify(s.trustees_submitted) !== JSON.stringify(state.trustees_submitted)) await refresh();
  } catch { /* server restarting: try again next tick */ }
}
setInterval(poll, 3000);

function render() {
  const has = state.phase !== "none";
  $("setup").hidden = has && !showSetup;
  $("election").hidden = !has || showSetup;
  $("new-btn").hidden = !has || showSetup;
  $("cancel-setup").hidden = !has;
  renderStepper();
  if (!has) return;
  renderOverview();
  renderTabs();
  renderAuthority();
  renderBooth();
  renderTrustees();
  renderTally();
  renderBoard();
}

function renderStepper() {
  const cur = { none: 0, open: 1, closed: 2, tallied: report?.ok ? 4 : 3 }[state.phase];
  const steps = ["Keys", "Voting", "Decrypt", "Verified"];
  $("stepper").replaceChildren(...steps.map((label, i) => {
    const status = i < cur ? "done" : i === cur ? "current" : "todo";
    return el("li", { class: status }, el("span", { class: "dot" }, status === "done" ? "✓" : String(i + 1)), el("span", {}, label));
  }));
}

function renderOverview() {
  const pct = state.voters ? Math.round((100 * state.ballots) / state.voters) : 0;
  $("ov-id").textContent = `Election ${state.election_id} · ${state.phase === "open" ? "polls open" : state.phase === "closed" ? "polls closed" : "tallied"}`;
  $("ov-title").textContent = state.title;
  $("st-turnout").textContent = `${pct}%`;
  const C = 2 * Math.PI * 18;
  $("ring-fg").style.strokeDasharray = `${(C * pct) / 100} ${C}`;
  $("ring-fg").style.opacity = pct ? 1 : 0;
  $("st-registered").textContent = `${state.registered}/${state.voters}`;
  $("st-board").textContent = String(state.board_length);
  $("st-head").replaceChildren(fingerprint(state.board_head, 8));
  $("st-head").title = `chain head ${state.board_head}`;
  $("st-crypto").textContent = `${state.paillier_bits}-bit`;
  $("st-crypto-label").textContent = `Paillier · ${plural(state.trustees, "trustee")}`;
  $("tab-board-count").textContent = String(state.board_length);
  $("board-head").textContent = state.board_head;
  $("storage-note").textContent = state.board_id
    ? `Stored in ${state.storage} · board id ${state.board_id}`
    : "Stored in memory only: this board is lost when the server stops.";
}

function renderTabs() {
  for (const b of document.querySelectorAll("[data-tab]")) {
    const on = b.dataset.tab === tab;
    b.setAttribute("aria-selected", on);
    b.classList.toggle("on", on);
  }
  for (const p of document.querySelectorAll("[data-panel]")) p.hidden = p.dataset.panel !== tab;
}

function setTab(name) {
  tab = name;
  store("tab", name);
  history.replaceState(null, "", `#${name}`);
  renderTabs();
}

// ---------------------------------------------------------------- authority
function renderAuthority() {
  const w = myWallet();
  const isAdmin = Boolean(w.admin_token && adminRoll);
  $("not-admin").hidden = isAdmin;
  $("authority").hidden = !isAdmin;
  if (!isAdmin) return;
  const open = state.phase === "open";
  const registered = adminRoll.filter((r) => r.registered).length;
  $("codes-sum").textContent = `${registered} of ${adminRoll.length} registered · ${adminRoll.filter((r) => r.voted).length} voted`;
  $("register-all").disabled = !open || registered === adminRoll.length;
  $("codes").replaceChildren(...adminRoll.map((r) => el("li", { class: r.voted ? "voted" : r.registered ? "reg" : "" },
    el("span", { class: "code-name" }, r.name),
    el("code", { class: "code-val" }, r.code),
    el("span", { class: `badge ${r.voted ? "ok" : r.registered ? "neutral" : "dim"}` }, r.voted ? "voted" : r.registered ? "registered" : "unused"),
    r.registered
      ? el("code", { class: "code-cred", title: r.credential_id }, short(r.credential_id, 10))
      : el("button", { type: "button", class: "btn ghost small", disabled: !open, onclick: () => registerCodes([r.code]) }, "Use on this device"),
  )));

  $("close-btn").disabled = !open;
  $("close-note").textContent = open
    ? `${plural(state.ballots, "ballot")} cast by ${state.registered} registered voters so far.`
    : "The polls are closed.";
  $("share-count").textContent = String(state.trustees);
  $("share-files").replaceChildren(...Array.from({ length: state.trustees }, (_, j) => {
    const share = (w.shares || [])[j];
    return el("li", {},
      el("span", { class: "share-ico" }, "⚿"),
      el("span", { class: "share-text" }, el("strong", {}, `Trustee ${j + 1}`),
        el("span", {}, share ? `share ${mid(share.share, 10, 6)} · ${share.share.length * 4} bits` : "not on this device")),
      share ? el("button", { type: "button", class: "btn ghost small", onclick: () => download(`trustee-${j + 1}-${state.election_id}.json`, share) }, "Download") : null);
  }));
}

async function registerCodes(codes) {
  if (!codes.length) return;
  await busy(codes.length > 1 ? `Registering ${codes.length} voter devices` : "Registering a voter device", [
    `Generating a ${VOTER_KEY_BITS}-bit RSA key pair in this browser (the private key never leaves it)`,
    "Sending the public key with the one-time code; the authority signs a credential",
    "Checking the authority's signature on the credential before trusting it",
  ], async (log) => {
    for (const [i, code] of codes.entries()) {
      const dev = await registerDevice(code);
      if (codes.length > 1) log(`${i + 1}/${codes.length}: ${dev.name} registered (${short(dev.credential_id, 10)})`);
    }
    await refresh();
    toast(codes.length > 1 ? `${codes.length} devices registered` : "Device registered: credential signed by the authority");
  });
}

async function registerDevice(code) {
  const key = await work("keygen", { bits: VOTER_KEY_BITS });
  const res = await api("/api/register", { code, voter_public_key: key.public_key });
  const cred = res.credential;
  // Trust nothing: the credential must be for our key and carry a valid authority signature.
  const auth = electionEntry().payload.authority_public_key;
  const payload = { election_id: cred.election_id, credential_id: cred.credential_id, voter_public_key: cred.voter_public_key };
  const sigOk = GB.rsaVerify({ n: GB.fromHex(auth.n), e: GB.fromHex(auth.e) }, GB.canonicalBytes(payload), GB.fromHex(cred.signature));
  if (cred.credential_id !== key.credential_id || !sigOk) throw new Error("the server returned a credential that does not check out");
  const device = { name: res.name, credential_id: cred.credential_id, credential: cred, private_key: key.private_key, keygen_ms: key.ms, seq: res.seq };
  wallet.update(state.election_id, (w) => { w.devices = [...(w.devices || []), device]; });
  if (!selectedDevice) selectedDevice = device.credential_id;
  return device;
}

// ---------------------------------------------------------------- booth
function renderBooth() {
  const open = state.phase === "open";
  const devices = myWallet().devices || [];
  const voted = votedSet();
  if (!devices.some((d) => d.credential_id === selectedDevice)) {
    selectedDevice = (devices.find((d) => !voted.has(d.credential_id)) || devices[0])?.credential_id || null;
  }
  $("devices-sum").textContent = devices.length ? `${devices.filter((d) => voted.has(d.credential_id)).length} of ${devices.length} voted` : "";
  $("devices").replaceChildren(...(devices.length ? devices.map((d) => el("button", {
    type: "button", role: "radio",
    class: `voter${d.credential_id === selectedDevice ? " on" : ""}${voted.has(d.credential_id) ? " voted" : ""}`,
    "aria-checked": d.credential_id === selectedDevice,
    title: `credential ${d.credential_id}`,
    onclick: () => { selectedDevice = d.credential_id; sealed = null; renderBooth(); },
  },
  identicon(d.credential_id),
  el("span", { class: "voter-text" }, el("span", { class: "voter-name" }, d.name), el("code", { class: "voter-cred" }, short(d.credential_id, 8))),
  el("span", { class: "voter-state" }, voted.has(d.credential_id) ? "✓" : ""),
  )) : [el("p", { class: "empty" }, "No voter devices in this browser yet. Register one with a code below, or from the Authority tab.")]));

  const device = devices.find((d) => d.credential_id === selectedDevice);
  $("ballot-title").textContent = state.title;
  $("ballot-voter").replaceChildren(...(device
    ? ["Voting as ", el("strong", {}, device.name), " · credential ", el("code", {}, short(device.credential_id, 12))]
    : ["No device selected"]));

  const choices = $("choices");
  const picked = choices.querySelector("input:checked")?.value;
  const locked = !open || !device || voted.has(device?.credential_id) || Boolean(sealed);
  choices.replaceChildren(el("legend", { class: "sr" }, "Choose one candidate"),
    ...state.candidates.map((name, i) => el("label", { class: "choice" },
      el("input", { type: "radio", name: "choice", value: i, checked: String(i) === picked || sealed?.choice === i, disabled: locked }),
      el("span", { class: "avatar", style: `--h:${(i * 137 + 190) % 360}` }, initials(name)),
      el("span", { class: "choice-name" }, name),
      el("span", { class: "mark", "aria-hidden": "true" }))));

  const warn = !open ? "The polls are closed."
    : !device ? "Register a voter device first."
      : voted.has(device.credential_id) ? "This device's credential already has a ballot on the board. The server, the database and the verifier would all reject a second one."
        : null;
  $("booth-warn").hidden = !warn;
  $("booth-warn").textContent = warn || "";
  $("encrypt-btn").disabled = locked;

  renderSealed();
  renderReveal();
}

function renderSealed() {
  $("sealed").hidden = !sealed || sealed.credential_id !== selectedDevice;
  if ($("sealed").hidden) return;
  $("sealed-time").textContent = sealed.ms ? `encrypted + proved in ${secs(sealed.ms)}` : "encrypting…";
  $("sealed-fp").replaceChildren(sealed.fingerprint ? fingerprint(sealed.fingerprint, 8) : "");
  $("sealed-hash").textContent = sealed.fingerprint ? mid(sealed.fingerprint, 16, 8) : "…";
  $("sealed-ciphers").replaceChildren(...state.candidates.map((name, i) => {
    const c = sealed.body?.ciphertexts[i] || sealed.progress?.[i]?.ciphertext;
    const proven = Boolean(sealed.body) || sealed.progress?.[i]?.proven;
    return el("li", { class: c ? "in" : "wait", style: `--i:${i}` },
      el("div", { class: "cipher-head" },
        el("span", {}, `c${sub(i + 1)} · ${name}`),
        el("span", { class: `badge ${proven ? "ok" : "neutral"}` }, proven ? "proved 0 or 1" : c ? "proving…" : "encrypting…")),
      el("code", { class: "cipher" }, c || "…"));
  }));
  const ready = Boolean(sealed.body);
  for (const id of ["cast-btn", "audit-btn"]) $(id).disabled = !ready;
}

function renderReveal() {
  const show = lastCast && lastCast.credential_id === selectedDevice && ballotOf(lastCast.credential_id);
  $("reveal").hidden = !show;
  if (!show) return;
  $("receipt-value").textContent = lastCast.receipt;
  $("ticket-fp").replaceChildren(fingerprint(lastCast.receipt, 8));
  const k = state.candidates.length;
  $("ticket-checks").replaceChildren(
    el("li", {}, `${k} ciphertexts, each proven to hold 0 or 1`),
    el("li", {}, "Sum proof: exactly one of them is 1"),
    el("li", {}, `Signed on this device with credential ${short(lastCast.credential_id, 10)}`),
    el("li", { class: lastCast.receiptMatches ? "" : "bad" }, lastCast.receiptMatches
      ? "The receipt this device computed matches the server's"
      : "The server's receipt differs from this device's. Do not trust this server!"),
    el("li", {}, `Chained into the board as block #${lastCast.seq}`),
  );
  $("ticket-time").textContent = `encrypt ${secs(lastCast.encMs)} · sign ${secs(lastCast.signMs)} · server check ${lastCast.seconds}s`;
  $("reveal-board").onclick = () => focusBlock(lastCast.seq);
}

$("vote-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const choice = new FormData(ev.target).get("choice");
  if (choice === null) return toast("Pick a candidate first", "error");
  const device = myWallet().devices.find((d) => d.credential_id === selectedDevice);
  $("audit-card").hidden = true;
  lastCast = null;
  sealed = { credential_id: device.credential_id, choice: Number(choice), progress: [] };
  renderBooth();
  try {
    const out = await work("encrypt", {
      n: paillierN(), election_id: state.election_id, credential_id: device.credential_id,
      num_candidates: state.candidates.length, choice: Number(choice),
    }, (p) => {
      if (!sealed) return;
      if (p.step === "prove") sealed.progress[p.candidate] = { ciphertext: p.ciphertext };
      if (p.step === "encrypt" && p.candidate > 0) sealed.progress[p.candidate - 1].proven = true;
      if (p.step === "sum") sealed.progress[sealed.progress.length - 1].proven = true;
      renderSealed();
    });
    if (!sealed) return;
    Object.assign(sealed, out);
    renderBooth();
    $("sealed").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (err) {
    sealed = null;
    renderBooth();
    toast(err.message, "error");
  }
});

$("discard-btn").addEventListener("click", () => { sealed = null; renderBooth(); });

$("cast-btn").addEventListener("click", () => {
  const s = sealed;
  const device = myWallet().devices.find((d) => d.credential_id === s.credential_id);
  busy(`Casting ${device.name}'s ballot`, [
    "Signing the ballot with this device's RSA key (PKCS#1 v1.5, SHA-256)",
    "Server checks: credential on the roll, not yet voted, signature, every zero-knowledge proof",
    "Server appends it to the hash-chained board",
  ], async () => {
    const signed = await work("sign", { private_key: device.private_key, body: s.body });
    const res = await api("/api/vote", { ballot: signed.signed });
    lastCast = { credential_id: s.credential_id, receipt: res.receipt, seq: res.seq, seconds: res.seconds,
      encMs: s.ms, signMs: signed.ms, receiptMatches: res.receipt === signed.receipt };
    wallet.update(state.election_id, (w) => {
      const d = w.devices.find((x) => x.credential_id === s.credential_id);
      if (d) d.receipt = res.receipt;
    });
    sealed = null;
    $("choices").querySelectorAll("input").forEach((i) => { i.checked = false; });
    await refresh();
    toast(`Ballot accepted and on the board (block #${res.seq})`);
    $("reveal").scrollIntoView({ behavior: "smooth", block: "nearest" });
  });
});

$("audit-btn").addEventListener("click", () => {
  const s = sealed;
  busy("Auditing the sealed ballot", [
    "Revealing the randomness rᵢ behind each ciphertext (this ballot is now spoiled)",
    "Re-encrypting the claimed choice in this browser",
    "Asking the server's independent Python code to do the same",
  ], async () => {
    const mine = await work("audit", { n: paillierN(), body: s.body, choice: s.choice, randomness: s.randomness });
    const server = await api("/api/audit", { body: s.body, choice: s.choice, randomness: s.randomness });
    sealed = null;
    renderBooth();
    $("audit-rows").replaceChildren(...state.candidates.map((name, i) => el("li", {},
      el("div", { class: "audit-head" },
        el("strong", {}, name),
        el("span", { class: "muted small" }, `claimed m = ${i === s.choice ? 1 : 0}`)),
      el("div", { class: "audit-math" },
        el("span", { class: "muted small" }, "r ="), el("code", {}, mid(s.randomness[i], 18, 8)),
        el("span", { class: "muted small" }, "c ="), el("code", {}, mid(s.body.ciphertexts[i], 18, 8))),
      el("div", { class: "audit-checks" },
        el("span", { class: `badge ${mine[i] ? "ok" : "bad"}` }, `browser: ${mine[i] ? "opens" : "does not open"}`),
        el("span", { class: `badge ${server.opens[i] ? "ok" : "bad"}` }, `server: ${server.opens[i] ? "opens" : "does not open"}`)))));
    const ok = mine.every(Boolean) && server.ok;
    $("audit-verdict").className = `audit-verdict ${ok ? "ok" : "fail"}`;
    $("audit-verdict").textContent = ok
      ? `✓ The device encrypted exactly "${server.candidate}". Proofs: ${server.proofs}. Since the device could not know in advance whether you would audit, a cheating device would get caught.`
      : "✕ The ciphertexts do NOT match the choice you made. This device is cheating. Do not cast from it.";
    $("audit-card").hidden = false;
    $("audit-card").scrollIntoView({ behavior: "smooth", block: "nearest" });
  });
});

$("audit-again").addEventListener("click", () => { $("audit-card").hidden = true; });

$("register-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const code = new FormData(ev.target).get("code").trim();
  if (!code) return toast("Enter a registration code", "error");
  registerCodes([code]).then(() => { ev.target.reset(); });
});

$("register-all").addEventListener("click", () => {
  registerCodes(adminRoll.filter((r) => !r.registered).map((r) => r.code)).then(() => setTab("booth"));
});

$("copy-receipt").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("receipt-value").textContent);
    toast("Receipt copied");
  } catch {
    toast("Copy failed: select the receipt text instead", "error");
  }
});

// ---------------------------------------------------------------- close
let closeArmed = null;
$("close-btn").addEventListener("click", () => {
  const btn = $("close-btn");
  const reset = () => { closeArmed = null; btn.textContent = "Close polls"; btn.classList.remove("armed"); };
  if (!closeArmed) {
    btn.textContent = `Confirm: close with ${plural(state.ballots, "ballot")}`;
    btn.classList.add("armed");
    closeArmed = setTimeout(reset, 4000);
    return;
  }
  clearTimeout(closeArmed);
  reset();
  busy("Closing the polls", ["Posting a close entry that commits to the board head and the ballot count"], async () => {
    await api("/api/close", {}, adminHeaders());
    sealed = null;
    await refresh();
    setTab("trustees");
    toast("Polls closed. Now each trustee decrypts their share.");
  });
});

// ---------------------------------------------------------------- trustees
function renderTrustees() {
  const w = myWallet();
  const submitted = state.trustees_submitted || [];
  $("trustee-sum").textContent = `${submitted.filter(Boolean).length} of ${state.trustees} partial decryptions in`;
  $("trustees").replaceChildren(...Array.from({ length: state.trustees }, (_, j) => {
    const share = (w.shares || [])[j];
    const out = (w.trusteeOut || {})[j];
    const done = submitted[j] || state.phase === "tallied";
    const status = state.phase === "open" ? "waiting for the polls to close"
      : done ? "partial decryption submitted" : share ? "ready to decrypt" : "share not on this device";
    return el("li", { class: `trustee${done ? " done" : ""}` },
      el("div", { class: "trustee-head" },
        el("span", { class: "trustee-ico" }, done ? "✓" : "⚿"),
        el("span", { class: "share-text" }, el("strong", {}, `Trustee ${j + 1}`), el("span", {}, status)),
        share && state.phase === "closed" && !done
          ? el("button", { type: "button", class: "btn primary small", onclick: () => trusteeDecrypt(j) }, "Decrypt my share")
          : null),
      share ? el("div", { class: "trustee-share" }, el("span", { class: "muted small" }, "secret share (never leaves this device)"),
        el("code", {}, mid(share.share, 22, 8))) : null,
      out ? el("ol", { class: "partials" }, ...out.partials.map((p, i) => el("li", {},
        el("span", { class: "muted small" }, `P${sub(j + 1)} for ${state.candidates[i]}`), el("code", {}, mid(p, 18, 6))))) : null,
    );
  }));
}

function trusteeDecrypt(j) {
  const share = myWallet().shares[j];
  busy(`Trustee ${j + 1}: partial decryption`, [
    "Downloading the public board and recomputing every encrypted total Tᵢ = Π cᵢ itself",
    "Computing Pⱼ = (Tᵢ mod n)^sⱼ mod n for each candidate with the secret share",
    "Submitting the partials (the share itself never leaves this device)",
  ], async () => {
    await refresh();
    if (!board.some((e) => e.kind === "close")) throw new Error("the board has no close entry yet");
    const bodies = board.filter((e) => e.kind === "ballot").map((e) => e.payload.body);
    const out = await work("trustee", { n: share.n, share: share.share, bodies, num_candidates: state.candidates.length });
    const res = await api("/api/trustee/partial", { trustee: j, token: share.token, partials: out.partials });
    wallet.update(state.election_id, (w) => { w.trusteeOut = { ...(w.trusteeOut || {}), [j]: out }; });
    await refresh();
    if (res.published) {
      setTab("tally");
      toast("All trustees are in: the totals are opened and published");
    } else {
      toast(`Trustee ${j + 1} submitted. Waiting for the others.`);
    }
  });
}

$("share-file").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  ev.target.value = "";
  if (!file) return;
  try {
    const share = JSON.parse(await file.text());
    if (share.election_id !== state.election_id) throw new Error("that share belongs to a different election");
    if (!(share.trustee >= 0 && share.trustee < state.trustees) || !share.share || !share.token) throw new Error("not a trustee share file");
    wallet.update(state.election_id, (w) => { w.shares = w.shares || []; w.shares[share.trustee] = share; });
    renderTrustees();
    toast(`Loaded the share of trustee ${share.trustee + 1}`);
  } catch (err) {
    toast(err.message, "error");
  }
});

// ---------------------------------------------------------------- results + audit
function renderTally() {
  const tallied = state.phase === "tallied";
  $("tally-waiting").hidden = tallied;
  $("tally-done").hidden = !tallied;
  if (!tallied) {
    const n = (state.trustees_submitted || []).filter(Boolean).length;
    $("tally-waiting-text").textContent = state.phase === "open"
      ? `Voting is open (${plural(state.ballots, "ballot")} so far). Results appear after the authority closes the polls and all ${state.trustees} trustees submit their partial decryptions.`
      : `The polls are closed. ${n} of ${state.trustees} trustees have submitted partial decryptions. The totals open only when all of them have.`;
    const next = state.phase === "open" ? ["authority", "Next step: close the polls (Authority tab) →"] : ["trustees", "Next step: trustee decryption (Trustees tab) →"];
    $("tally-next").textContent = next[1];
    $("tally-next").onclick = () => setTab(next[0]);
    return;
  }
  const results = state.results;
  const sum = results.reduce((a, r) => a + r.total, 0);
  const max = Math.max(...results.map((r) => r.total));
  const enc = board.find((e) => e.kind === "result")?.payload.results || [];
  $("results-sum").textContent = `${plural(sum, "vote")} · ${state.voters ? Math.round((100 * state.ballots) / state.voters) : 0}% turnout`;
  const list = $("results");
  const first = list.dataset.shown !== state.election_id;
  list.dataset.shown = state.election_id;
  list.replaceChildren(...results.map((r, i) => {
    const pct = sum ? (100 * r.total) / sum : 0;
    const win = r.total === max && max > 0;
    const bar = el("span", { class: "fill", style: `width:${first ? 0 : pct}%` });
    if (first) requestAnimationFrame(() => requestAnimationFrame(() => { bar.style.width = `${pct}%`; }));
    return el("li", { class: win ? "win" : "" },
      el("div", { class: "res-line" },
        el("span", { class: "res-name" }, r.name, win ? el("span", { class: "crown", title: "most votes" }, "★") : null),
        el("span", { class: "res-num" }, el("strong", {}, String(r.total)), ` · ${pct.toFixed(0)}%`)),
      el("div", { class: "bar" }, bar),
      enc[i] ? el("div", { class: "res-enc" },
        el("span", {}, "T ="), el("code", { title: enc[i].encrypted_total }, short(enc[i].encrypted_total, 14)),
        el("span", {}, "· R = Π partials ="), el("code", { title: enc[i].randomness }, short(enc[i].randomness, 12)),
        el("span", {}, "· gᵐ·Rⁿ = T ⇒ m ="), el("strong", {}, String(r.total))) : null);
  }));
  if (!report) {
    $("checks").replaceChildren();
    $("seal").hidden = true;
    $("verify-btn").textContent = "Run the verifier";
  }
}

$("verify-btn").addEventListener("click", () => {
  busy("Running the public verifier", [
    "Walking the hash chain from the first block",
    "Checking every credential, voter signature and zero-knowledge proof",
    "Recomputing the homomorphic tally and opening it with the trustees' partials",
  ], async () => {
    report = await api("/api/verify");
    $("checks").replaceChildren(...report.checks.map((c, i) => el("li", { class: c.ok ? "ok" : "fail", style: `--i:${i}` },
      el("span", { class: "check-icon" }, c.ok ? "✓" : "✕"),
      el("span", {}, el("strong", {}, c.name), el("span", { class: "check-detail" }, c.detail)))));
    const seal = $("seal");
    seal.className = `seal ${report.ok ? "ok" : "fail"}`;
    seal.style.setProperty("--i", report.checks.length);
    seal.replaceChildren(
      el("span", { class: "seal-icon" }, report.ok ? "✓" : "✕"),
      el("span", {}, el("strong", {}, report.ok ? "Election verified" : "Verification failed"),
        el("span", {}, report.ok ? `All ${report.checks.length} checks pass on the board alone.` : "At least one check failed. Do not trust these results.")));
    seal.hidden = false;
    $("verify-btn").textContent = "Run again";
    renderStepper();
  });
});

$("receipt-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("receipt-result");
  try {
    const res = await api("/api/receipt", { receipt: new FormData(ev.target).get("receipt") });
    out.className = `lookup-result ${res.found ? "found" : "missing"}`;
    out.replaceChildren(...(res.found
      ? ["✓ Found at board block ", el("strong", {}, `#${res.seq}`), " ",
        el("button", { type: "button", class: "btn ghost small", onclick: () => focusBlock(res.seq) }, "Show block →")]
      : ["✕ No ballot with this receipt is on the board."]));
  } catch (err) {
    out.className = "lookup-result missing";
    out.textContent = err.message;
  }
});

// ---------------------------------------------------------------- board
function describe(e) {
  const p = e.payload;
  switch (e.kind) {
    case "election":
      return [`Election opened: ${p.title}`, `${plural(p.candidates.length, "candidate")} · ${plural(p.trustees, "trustee")} · Paillier ${Math.round((p.paillier_public_key.n.length * 4) / 256) * 256}-bit and authority RSA public keys`];
    case "credential": {
      const who = nameOf(p.credential_id);
      return [`Credential issued${who ? ` · ${who.name} (${who.how})` : ""}`, `voter's public key, signed by the authority · id ${short(p.credential_id, 12)}`];
    }
    case "ballot": {
      const who = nameOf(p.body.credential_id);
      const k = p.body.ciphertexts.length;
      return [`Encrypted ballot${who ? ` · ${who.name} (${who.how})` : ""}`, `${k} ciphertexts · ${k + 1} zero-knowledge proofs · voter signature`];
    }
    case "close":
      return ["Polls closed", `${plural(p.ballot_count, "ballot")} accepted · commits to head ${short(p.board_head, 10)}`];
    case "result":
      return ["Tally opened by the trustees", `${p.results.map((r) => `${r.name} ${r.total}`).join(" · ")} · ${plural(p.results[0]?.partials.length || 0, "partial")} per total`];
    default:
      return [e.kind, ""];
  }
}

const FILTERS = { all: null, credential: ["credential"], ballot: ["ballot"], tally: ["election", "close", "result"] };

function renderBoard() {
  for (const b of document.querySelectorAll("[data-filter]")) {
    b.classList.toggle("on", b.dataset.filter === boardFilter);
    b.setAttribute("aria-selected", b.dataset.filter === boardFilter);
  }
  const kinds = FILTERS[boardFilter];
  const openSeqs = new Set([...document.querySelectorAll("#chain details[open]")].map((d) => d.dataset.seq));
  $("chain").replaceChildren(...board.filter((e) => !kinds || kinds.includes(e.kind)).map((e) => {
    const [title, subline] = describe(e);
    const det = el("details", { "data-seq": e.seq, open: openSeqs.has(String(e.seq)) },
      el("summary", {},
        el("span", { class: "seq" }, `#${e.seq}`),
        el("span", { class: `kind kind-${e.kind}` }, e.kind),
        el("span", { class: "blk-text" }, el("strong", {}, title), el("span", {}, subline)),
        el("span", { class: "links" },
          el("span", { class: "link" }, el("small", {}, "prev"), fingerprint(e.prev_hash, 4)),
          el("span", { class: "link" }, el("small", {}, "hash"), fingerprint(e.entry_hash, 4)))),
      el("div", { class: "blk-body" },
        el("dl", { class: "hashes" },
          el("dt", {}, "prev_hash"), el("dd", {}, el("code", {}, e.prev_hash)),
          el("dt", {}, "entry_hash"), el("dd", {}, el("code", {}, e.entry_hash))),
        jsonView(e.payload)));
    return el("li", { id: `blk-${e.seq}`, class: `blk blk-${e.kind}` }, det);
  }));
}

function jsonView(obj) {
  const text = JSON.stringify(obj, (k, v) => (typeof v === "string" && v.length > 64
    ? `${v.slice(0, 28)}…${v.slice(-10)} ⟨${v.length * 4} bits⟩` : v), 2);
  const pre = el("pre", { class: "json" });
  const re = /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?)/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    pre.append(text.slice(last, m.index));
    if (m[1]) {
      pre.append(el("span", { class: m[2] ? "j-key" : "j-str" }, m[1]));
      if (m[2]) pre.append(m[2]);
    } else {
      pre.append(el("span", { class: m[3] ? "j-lit" : "j-num" }, m[0]));
    }
    last = m.index + m[0].length;
  }
  pre.append(text.slice(last));
  return pre;
}

function focusBlock(seq) {
  boardFilter = "all";
  setTab("board");
  renderBoard();
  const li = $(`blk-${seq}`);
  if (!li) return;
  li.querySelector("details").open = true;
  li.classList.remove("flash");
  void li.offsetWidth;
  li.classList.add("flash");
  li.scrollIntoView({ behavior: "smooth", block: "center" });
}

// ---------------------------------------------------------------- stored elections
async function refreshArchive() {
  const stored = await api("/api/elections");
  $("archive").hidden = !stored.length;
  $("archive-where").textContent = state.storage || "";
  $("archive-list").replaceChildren(...stored.map((b) => {
    const out = el("span", { class: "archive-out" });
    const current = b.board_id === state.board_id;
    return el("li", {},
      fingerprint(b.head, 4),
      el("span", { class: "archive-text" },
        el("strong", {}, b.title || "Untitled", current ? el("span", { class: "badge ok now" }, "current") : null),
        el("span", {}, `${new Date(b.created_at).toLocaleString()} · ${plural(b.ballots, "ballot")} · ${plural(b.entries, "entry")}`)),
      el("span", { class: "archive-actions" },
        out,
        b.tallied
          ? el("button", { type: "button", class: "btn ghost small", onclick: () => verifyStored(b.board_id, out) }, "Verify")
          : el("span", { class: "muted small" }, current ? "in progress" : "never tallied"),
        el("a", { class: "btn ghost small", href: `/api/elections/${b.board_id}/board.jsonl`, download: true, title: "Download board" }, "↓")));
  }));
}

async function verifyStored(boardId, out) {
  out.className = "archive-out";
  out.textContent = "checking…";
  try {
    const rep = await api(`/api/elections/${boardId}/verify`);
    out.className = `archive-out ${rep.ok ? "found" : "missing"}`;
    out.textContent = rep.ok
      ? `✓ verified · ${rep.results.map((r) => `${r.name} ${r.total}`).join(", ")}`
      : `✕ ${rep.checks.find((c) => !c.ok)?.name || "failed"}`;
  } catch (err) {
    out.className = "archive-out missing";
    out.textContent = err.message;
  }
}

// ---------------------------------------------------------------- setup
function candRow(value = "") {
  const li = el("li", {},
    el("span", { class: "grip", "aria-hidden": "true" }),
    el("input", { name: "candidate", value, placeholder: "Candidate name", maxlength: 40, "aria-label": "Candidate name" }),
    el("button", { type: "button", class: "icon-btn sm", title: "Remove", "aria-label": "Remove candidate", onclick: () => {
      if ($("cand-list").children.length > 2) li.remove();
      else toast("An election needs at least two candidates", "error");
    } }, "×"));
  return li;
}
$("cand-list").append(...["Alice", "Bob", "Carol"].map(candRow));
$("add-cand").addEventListener("click", () => {
  if ($("cand-list").children.length >= 12) return toast("At most 12 candidates", "error");
  const row = candRow();
  $("cand-list").append(row);
  row.querySelector("input").focus();
});

for (const [rangeId, outId] of [["voters-range", "voters-out"], ["trustees-range", "trustees-out"]]) {
  const range = $(rangeId);
  const sync = () => {
    $(outId).textContent = range.value;
    range.style.setProperty("--p", `${((range.value - range.min) / (range.max - range.min)) * 100}%`);
  };
  range.addEventListener("input", sync);
  sync();
}

$("setup-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const body = {
    title: f.get("title"),
    candidates: f.getAll("candidate").map((s) => s.trim()).filter(Boolean),
    voters: Number(f.get("voters")),
    trustees: Number(f.get("trustees")),
    paillier_bits: Number(f.get("paillier_bits")),
  };
  if (body.candidates.length < 2) return toast("Enter at least two candidates", "error");
  busy("Running the key ceremony", [
    `Generating the ${body.paillier_bits}-bit Paillier election key`,
    `Splitting its decryption exponent into ${plural(body.trustees, "trustee share")}, then deleting the key`,
    "Generating the authority's 2048-bit RSA signing key",
    `Creating ${plural(body.voters, "one-time registration code")}`,
  ], async () => {
    const res = await api("/api/election", body);
    wallet.update(res.election_id, (w) => {
      w.admin_token = res.admin_token;
      w.shares = res.trustee_shares;
      w.devices = w.devices || [];
    });
    showSetup = false;
    report = null; sealed = null; lastCast = null;
    $("receipt-result").replaceChildren();
    $("audit-card").hidden = true;
    await refresh();
    showHandover(res);
  });
});

function showHandover(res) {
  $("handover-text").textContent = `"${res.title}" is open (election ${res.election_id}), built in ${res.seconds}s. This browser now plays every role:`;
  $("handover-list").replaceChildren(
    el("li", {}, el("strong", {}, "Authority: "), "the admin token is stored on this device. Closing the polls and reading the codes need it."),
    el("li", {}, el("strong", {}, `${res.codes.length} registration codes: `), "one per voter, listed in the Authority tab."),
    el("li", {}, el("strong", {}, `${res.trustee_shares.length} trustee shares: `), "the decryption key no longer exists in one piece. Download each share for its trustee, or keep them in the Trustees tab for the demo."),
  );
  $("handover").hidden = false;
  $("handover-ok").focus();
}
$("handover-ok").addEventListener("click", () => { $("handover").hidden = true; setTab("authority"); });

function toggleSetup(on) {
  showSetup = on;
  render();
  if (on) refreshArchive().catch((err) => toast(err.message, "error"));
  window.scrollTo({ top: 0, behavior: "smooth" });
}
$("new-btn").addEventListener("click", () => toggleSetup(true));
$("not-admin-new").addEventListener("click", () => toggleSetup(true));
$("cancel-setup").addEventListener("click", () => toggleSetup(false));
$("brand").addEventListener("click", (ev) => { ev.preventDefault(); if (state.phase !== "none") toggleSetup(false); });

// ---------------------------------------------------------------- tabs, filters, theme
for (const b of document.querySelectorAll("[data-tab]")) b.addEventListener("click", () => setTab(b.dataset.tab));
for (const b of document.querySelectorAll("[data-filter]")) b.addEventListener("click", () => { boardFilter = b.dataset.filter; renderBoard(); });

$("theme-btn").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  store("theme", root.dataset.theme);
});

refresh().catch((err) => toast(err.message, "error"));
