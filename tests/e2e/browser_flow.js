// End-to-end check of the web app in headless Chrome (DevTools protocol; Node >= 22 for WebSocket).
//   node tests/e2e/browser_flow.js http://127.0.0.1:8765 out-dir
// Runs a whole election through the UI: key ceremony, registration, audit (Benaloh), voting,
// closing, three trustees decrypting, public verification. Fails on any page error or CSP violation.
"use strict";
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const BASE = process.argv[2] || "http://127.0.0.1:8765";
const OUT = process.argv[3] || ".";
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = 9333;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "gb-chrome-"));
  const chrome = spawn(CHROME, ["--headless=new", `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
    "--no-first-run", "--window-size=1280,1000", "--hide-scrollbars", "about:blank"], { stdio: "ignore" });
  let target;
  for (let i = 0; i < 50 && !target; i++) {
    await sleep(200);
    try { target = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === "page"); } catch { /* not up yet */ }
  }
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener("open", r));
  let id = 0;
  const waiting = new Map();
  const problems = [];
  ws.addEventListener("message", ({ data }) => {
    const msg = JSON.parse(data);
    if (msg.id && waiting.has(msg.id)) { waiting.get(msg.id)(msg); waiting.delete(msg.id); }
    if (msg.method === "Runtime.exceptionThrown") problems.push(`exception: ${msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text}`);
    if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") problems.push(`console: ${msg.params.entry.text} ${msg.params.entry.url || ""}`);
    if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") problems.push(`console.error: ${msg.params.args.map((a) => a.value ?? a.description).join(" ")}`);
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const n = ++id;
    waiting.set(n, (m) => (m.error ? reject(new Error(`${method}: ${m.error.message}`)) : resolve(m.result)));
    ws.send(JSON.stringify({ id: n, method, params }));
  });
  const js = async (expr) => {
    const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`page: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}\n  in: ${expr}`);
    return r.result.value;
  };
  const until = async (expr, what, ms = 60000) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) {
      if (await js(expr)) return;
      await sleep(150);
    }
    throw new Error(`timed out waiting for ${what}`);
  };
  const click = (sel) => js(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) throw new Error("no ${sel}"); if (e.disabled) throw new Error("disabled ${sel}"); e.click(); return true; })()`);
  const shot = async (name) => {
    const { data } = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
    fs.writeFileSync(path.join(OUT, `${name}.png`), Buffer.from(data, "base64"));
  };
  const step = (s) => console.log(`- ${s}`);

  await send("Runtime.enable"); await send("Log.enable"); await send("Page.enable");
  await send("Page.navigate", { url: BASE });
  await until("document.readyState === 'complete' && !!window.GB", "page load");
  await until("state.phase !== undefined && (state.phase === 'none' || !document.getElementById('new-btn').hidden)", "first render");
  if (await js("state.phase !== 'none'")) await click("#new-btn");
  await until("!document.getElementById('setup').hidden", "setup form");
  await shot("01-setup");

  step("key ceremony: 1024-bit key, 4 voters, 3 trustees");
  await js(`(() => {
    document.querySelector('[name=paillier_bits][value="1024"]').checked = true;
    const v = document.getElementById('voters-range'); v.value = 4; v.dispatchEvent(new Event('input'));
    document.querySelector('#setup-form button[type=submit]').click(); return true; })()`);
  await until("!document.getElementById('handover').hidden", "handover dialog");
  await shot("02-handover");
  await click("#handover-ok");
  await until("document.querySelectorAll('#codes li').length === 4", "4 registration codes");
  await shot("03-authority");

  step("register all 4 voter devices (2048-bit RSA keys made in the page)");
  await click("#register-all");
  await until("document.querySelectorAll('#devices .voter').length === 4 && document.getElementById('busy').hidden", "4 devices", 120000);
  const regs = await js("JSON.parse(localStorage.getItem('gb.e.' + state.election_id)).devices.map(d => d.private_key.n.length * 4)");
  if (!regs.every((b) => b === 2048)) throw new Error(`device keys are not 2048-bit: ${regs}`);

  const vote = async (choice, audit = false) => {
    await js("document.querySelector('#devices .voter:not(.voted)').click()");
    await js(`document.querySelectorAll('#choices input')[${choice}].click()`);
    await click("#encrypt-btn");
    await until("!document.getElementById('sealed').hidden && !document.getElementById('cast-btn').disabled", "sealed ballot");
    if (audit) {
      await shot("04-sealed");
      await click("#audit-btn");
      await until("!document.getElementById('audit-card').hidden", "audit result");
      const verdict = await js("document.getElementById('audit-verdict').className + ' | ' + document.getElementById('audit-verdict').textContent");
      if (!verdict.startsWith("audit-verdict ok")) throw new Error(`audit failed: ${verdict}`);
      await shot("05-audit");
      await click("#audit-again");
      return;
    }
    await click("#cast-btn");
    await until("!document.getElementById('reveal').hidden && document.getElementById('busy').hidden", "receipt");
    const matches = await js("!document.querySelector('#ticket-checks li.bad')");
    if (!matches) throw new Error("device receipt does not match the server's");
  };
  step("voter 1 audits a ballot (Benaloh challenge), then votes for Bob");
  await vote(1, true);
  await vote(1);
  await shot("06-cast");
  step("voters 2-3 vote Alice, Carol; voter 4 abstains");
  await vote(0);
  await vote(2);

  step("double vote from the UI is blocked");
  await js("document.querySelector('#devices .voter').click()");
  if (!(await js("document.getElementById('encrypt-btn').disabled"))) throw new Error("voted device could vote again");

  step("authority closes the polls");
  await js("setTab('authority')");
  await click("#close-btn"); await click("#close-btn");
  await until("state.phase === 'closed' && document.getElementById('busy').hidden", "closed");
  await shot("07-trustees");

  step("three trustees decrypt their shares");
  for (let j = 0; j < 3; j++) {
    await until(`!!document.querySelectorAll('#trustees .trustee')[${j}].querySelector('button')`, `trustee ${j + 1} button`);
    await js(`document.querySelectorAll('#trustees .trustee')[${j}].querySelector('button').click()`);
    await until(`(state.trustees_submitted[${j}] || state.phase === 'tallied') && document.getElementById('busy').hidden`, `trustee ${j + 1}`);
  }
  await until("state.phase === 'tallied'", "tallied");
  const results = await js("state.results.map(r => r.name + '=' + r.total).join(', ')");
  if (results !== "Alice=1, Bob=1, Carol=1") throw new Error(`wrong results: ${results}`);

  step("public verifier");
  await click("#verify-btn");
  await until("!document.getElementById('seal').hidden", "verifier");
  await sleep(1800);   // let the check animation finish for the screenshot
  if (!(await js("document.getElementById('seal').classList.contains('ok')"))) throw new Error("verifier did not pass");
  await shot("08-verified");

  step("board view and receipt lookup");
  const receipt = await js("JSON.parse(localStorage.getItem('gb.e.' + state.election_id)).devices[0].receipt");
  await js(`(() => { const f = document.getElementById('receipt-form'); f.receipt.value = ${JSON.stringify(receipt)}; f.requestSubmit(); return true; })()`);
  await until("document.getElementById('receipt-result').classList.contains('found')", "receipt found");
  await js("setTab('board')");
  await js("document.querySelector('#chain details').open = true");
  await shot("09-board");

  step("How it works page: live values, every widget");
  await send("Page.navigate", { url: `${BASE}/learn.html` });
  await until("document.readyState === 'complete' && document.getElementById('live-pill').classList.contains('on')", "learn page with live data");
  await until("!!document.querySelector('.live-check.ok')", "live authority signature check");
  await until("document.querySelectorAll('#lr-body .badge.ok').length === 6", "live tally checks (3 candidates x 2)");
  await click("#ba-play");
  await until("document.querySelector('.ba-sig.in')", "ballot animation", 20000);
  await click("#tt-two");
  if (!(await js("document.querySelector('#tt-steps li.bad') !== null"))) throw new Error("2 of 3 trustees opened the toy total");
  await click("#tt-run");
  if (!(await js("document.querySelector('#tt-steps li.ok') !== null"))) throw new Error("3 trustees did not open the toy total");
  await click("#tp-tally");
  if (!(await js("document.querySelector('#tp-tally-steps li.ok .calc-v').textContent === 'm = 2'"))) throw new Error("toy Paillier tally wrong");
  await click("#tr-tamper");
  if (!(await js("document.querySelector('#tr-pipe .pipe.bad') !== null"))) throw new Error("tampered toy signature still verified");
  await js("(() => { const i = document.querySelectorAll('#chain-demo input')[1]; i.value = '{\"voter\":\"evil\"}'; i.dispatchEvent(new Event('change')); return true; })()");
  if (!(await js("document.querySelectorAll('#chain-demo .cblock.bad-content').length === 1"))) throw new Error("chain demo did not flag the edit");
  await js("document.querySelector('#chain-demo .cblock.bad-content button').click()");
  if (!(await js("document.querySelectorAll('#chain-demo .cblock.bad-link').length === 1"))) throw new Error("re-hash did not break the next link");
  await click("#arch-play");
  await sleep(6000);
  await js("document.querySelectorAll('.lsec').forEach(s => s.classList.add('seen'))");
  await sleep(800);
  await shot("10-learn");

  ws.close();
  chrome.kill();
  if (problems.length) {
    console.error("PAGE PROBLEMS:\n  " + problems.join("\n  "));
    process.exit(1);
  }
  console.log(`OK: ${results}; screenshots in ${OUT}`);
}

main().catch((err) => { console.error(err.message); process.exit(1); });
