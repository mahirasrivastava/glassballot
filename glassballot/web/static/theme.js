// Applied before first paint so a saved theme doesn't flash (a file, not inline: the CSP forbids inline scripts).
try { const t = localStorage.getItem("gb.theme"); if (t) document.documentElement.dataset.theme = t; } catch { /* no storage */ }
