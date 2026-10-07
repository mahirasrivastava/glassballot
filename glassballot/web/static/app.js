"use strict";

const $ = (id) => document.getElementById(id);
let state = { phase: "none" };
let showSetup = false;

// ------------------------------------------------------------------ api
async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

async function busy(text, fn) {
  $("busy-text").textContent = text;
  $("busy").hidden = false;
  try {
    return await fn();
  } catch (err) {
    toast(err.message, "error");
  } finally {
    $("busy").hidden = true;
  }
}

function toast(msg, kind = "info") {
  const t = $("toast");
  t.textContent = msg;
  t.className = `toast ${kind}`;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, kind === "error" ? 8000 : 4000);
}

// --------------------------------------------------------------- render
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
}

const short = (h, n = 10) => (h ? `${h.slice(0, n)}…` : "");

async function refresh() {
  state = await api("/api/state");
  render();
  if (state.phase !== "none") renderBoard(await api("/api/board"));
}

function render() {
  const has = state.phase !== "none";
  $("setup").hidden = has && !showSetup;
  $("election").hidden = !has;

  const status = $("status");
  status.replaceChildren();
  if (has) {
    status.append(
      el("span", {}, state.title),
      el("code", {}, state.election_id),
      el("span", { class: `pill ${state.phase}` }, state.phase === "open" ? "Voting open" : "Tallied"),
      el("button", { class: "btn small", type: "button", onclick: () => {
        showSetup = !showSetup;
        render();
        if (showSetup) $("setup").scrollIntoView({ behavior: "smooth" });
      } }, showSetup ? "Cancel" : "New election"),
    );
  }
  if (!has) return;

  const open = state.phase === "open";
  // voter select keeps its selection across refreshes
  const sel = $("voter-select");
  const prev = sel.value;
  sel.replaceChildren(...state.voters.map((v) =>
    el("option", { value: v.index }, `${v.name}${v.receipt ? " (voted)" : ""}`)));
  if (prev && prev < state.voters.length) sel.value = prev;

  const choices = $("choices");
  const picked = choices.querySelector("input:checked")?.value;
  choices.replaceChildren(el("legend", { class: "hint" }, "Choose one candidate"),
    ...state.candidates.map((name, i) => {
      const input = el("input", { type: "radio", name: "choice", value: i });
      if (String(i) === picked) input.checked = true;
      return el("label", { class: "choice" }, input, name);
    }));
  for (const n of $("vote-form").elements) n.disabled = !open;

  $("roll").replaceChildren(...state.voters.map((v) => el("tr", {},
    el("td", {}, v.name),
    el("td", {}, el("code", { title: v.credential_id }, short(v.credential_id))),
    el("td", {}, v.receipt
      ? el("span", { class: "voted", title: `receipt ${v.receipt}` }, "✓ voted")
      : el("span", { class: "waiting" }, "not yet")),
  )));

  $("tally-open").hidden = !open;
  $("tally-done").hidden = open;
  if (!open) {
    const max = Math.max(1, ...state.results.map((r) => r.total));
    $("results").replaceChildren(...state.results.map((r) => el("div", { class: "result" },
      el("span", { class: "name", title: r.name }, r.name),
      el("div", { class: "bar" }, el("span", { style: `width:${(100 * r.total) / max}%` })),
      el("span", { class: "num" }, String(r.total)),
    )));
  } else {
    $("checks").replaceChildren();
  }
}

// Long hex strings (ciphertexts, proofs, keys) are abbreviated for display.
function abbreviate(key, value) {
  if (typeof value === "string" && value.length > 48) {
    return `${value.slice(0, 20)}…${value.slice(-8)} (${value.length} hex)`;
  }
  return value;
}

function renderBoard(entries) {
  $("board").replaceChildren(...entries.map((e) => el("li", {},
    el("details", {},
      el("summary", {},
        el("span", { class: "seq" }, `#${e.seq}`),
        el("span", { class: `kind kind-${e.kind}` }, e.kind),
        el("span", { class: "hashes" }, `prev ${short(e.prev_hash, 8)} → hash ${short(e.entry_hash, 8)}`),
      ),
      el("pre", {}, JSON.stringify(e.payload, abbreviate, 2)),
    ),
  )));
}

// --------------------------------------------------------------- events
$("setup-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const body = {
    title: f.get("title"),
    candidates: f.get("candidates").split("\n").map((s) => s.trim()).filter(Boolean),
    voters: Number(f.get("voters")),
    paillier_bits: Number(f.get("paillier_bits")),
  };
  busy(`Generating keys and ${body.voters} voter credentials…`, async () => {
    const res = await api("/api/election", body);
    showSetup = false;
    $("receipt").hidden = true;
    $("receipt-result").textContent = "";
    await refresh();
    toast(`Election ready in ${res.seconds}s`);
  });
});

$("vote-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  if (f.get("choice") === null) return toast("Pick a candidate first", "error");
  busy("Encrypting ballot and proving it is well-formed…", async () => {
    const res = await api("/api/vote", { voter: Number(f.get("voter")), choice: Number(f.get("choice")) });
    $("receipt-value").textContent = res.receipt;
    $("receipt").hidden = false;
    ev.target.querySelectorAll("input[name=choice]").forEach((i) => { i.checked = false; });
    await refresh();
    // move on to the next voter who hasn't voted
    const next = state.voters.find((v) => !v.receipt);
    if (next) $("voter-select").value = next.index;
    toast(`Ballot accepted (${res.seconds}s)`);
  });
});

$("copy-receipt").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("receipt-value").textContent);
    toast("Receipt copied");
  } catch {
    toast("Copy failed: select the receipt text instead", "error");
  }
});

$("close-btn").addEventListener("click", () => {
  const cast = state.voters.filter((v) => v.receipt).length;
  if (!confirm(`Close the election with ${cast} of ${state.voters.length} ballots cast? No more votes after this.`)) return;
  busy("Aggregating ballots and decrypting the totals…", async () => {
    await api("/api/close", {});
    $("receipt").hidden = true;
    await refresh();
    toast("Election closed and tallied");
  });
});

$("verify-btn").addEventListener("click", () => {
  busy("Re-checking every signature and proof on the board…", async () => {
    const rep = await api("/api/verify");
    $("checks").replaceChildren(
      ...rep.checks.map((c) => el("li", { class: c.ok ? "ok" : "fail" },
        el("span", { class: "tag" }, c.ok ? "PASS" : "FAIL"),
        el("span", {}, el("strong", {}, c.name), `: ${c.detail}`))),
      el("li", { class: `verdict ${rep.ok ? "" : "fail"}` },
        rep.ok ? "ELECTION VERIFIED" : "ELECTION NOT VERIFIED"),
    );
  });
});

$("receipt-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("receipt-result");
  try {
    const res = await api("/api/receipt", { receipt: new FormData(ev.target).get("receipt") });
    out.className = `hint ${res.found ? "found" : "missing"}`;
    out.textContent = res.found
      ? `Found at board entry #${res.seq} (hash ${short(res.entry_hash, 16)}).`
      : "Not found on the board.";
  } catch (err) {
    out.className = "hint missing";
    out.textContent = err.message;
  }
});

refresh().catch((err) => toast(err.message, "error"));
