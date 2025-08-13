// /assets/js/jackpot.client.js
(() => {
  "use strict";

  // ---- single-run guard (avoid double inits)
  if (window.__L3Z_JACKPOT_INIT__) {
    console.warn("[jackpot] another instance already running; ignoring this one.");
    return;
  }
  window.__L3Z_JACKPOT_INIT__ = true;

  /* ================= DOM helpers ================= */
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  function getDigits() {
    // We expect exactly 6 digits (4 before dot, 2 after). Symbol "$" and the dot are excluded.
    const nodes = document.querySelectorAll(".reels .reel:not(.symbol) .digit");
    if (nodes.length !== 6) {
      console.warn("[jackpot] expected 6 digits, found", nodes.length, "— check markup/classes.");
    }
    return nodes;
  }

  function setSymbol(sym = "A$") {
    const el = document.querySelector(".reels .reel.symbol .digit");
    if (el) el.textContent = sym;
  }

  function renderAmount(aud) {
    const cents = Math.round((Number(aud) || 0) * 100);
    const s = String(cents).padStart(6, "0").slice(-6);
    const d = getDigits();
    if (d.length >= 6) {
      d[0].textContent = s[0]; // thousands
      d[1].textContent = s[1]; // hundreds
      d[2].textContent = s[2]; // tens
      d[3].textContent = s[3]; // ones
      d[4].textContent = s[4]; // .x
      d[5].textContent = s[5]; // .x
    }
  }

  /* ================= month window ================= */
  // Local month is fine for display; server uses Melbourne for resets and gives nextResetTs.
  const startOfMonth = (d = new Date()) => new Date(d.getFullYear(), d.getMonth(), 1, 0,0,0,0).getTime();
  const startOfNextMonth = (d = new Date()) => new Date(d.getFullYear(), d.getMonth()+1, 1, 0,0,0,0).getTime();

  /* ================= state ================= */
  // Base floor A$150 is pro-rated across the month, extras (subs/manual) are applied immediately.
  let baseFloorAUD = 150;   // server may override via /api/jackpot.base
  let extraAUD = 0;         // subs/manual snapshot from server (total - base)
  let mStart = startOfMonth();
  let mEnd   = startOfNextMonth();

  let displayAUD = 0;
  let lastTick = Date.now();

  const monthSpanMs = () => Math.max(1000, mEnd - mStart);
  const baseRatePerMs = () => baseFloorAUD / monthSpanMs();

  function targetNow(now = Date.now()) {
    const span = monthSpanMs();
    const elapsed = clamp(now - mStart, 0, span);
    const prorated = baseFloorAUD * (elapsed / span);
    return prorated + extraAUD;
  }

  // Smoothly animate to a new target
  function easeTo(target, ms = 900) {
    const start = displayAUD;
    const delta = target - start;
    if (Math.abs(delta) < 0.005) { // ~half cent
      displayAUD = target;
      renderAmount(displayAUD);
      return;
    }
    const t0 = performance.now();
    function step(t) {
      const k = clamp((t - t0) / ms, 0, 1);
      const e = 1 - Math.pow(1 - k, 3); // ease-out cubic
      displayAUD = start + delta * e;
      renderAmount(displayAUD);
      if (k < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  /* ================= server sync ================= */
  async function fetchJackpotSnapshot() {
    try {
      const r = await fetch("/api/jackpot", { cache: "no-store", credentials: "include" });
      if (!r.ok) throw new Error("status " + r.status);
      const j = await r.json();

      // server: { ok, currency:"AUD", month, base, subsCap, amount, nextResetTs }
      const srvBase   = Number(j.base ?? 150);
      const srvAmount = Number(j.amount ?? srvBase);
      const srvNext   = Number(j.nextResetTs || 0);

      baseFloorAUD = Number.isFinite(srvBase) ? srvBase : 150;
      // Extras are all contributions beyond the floor.
      extraAUD = Math.max(0, (Number.isFinite(srvAmount) ? srvAmount : baseFloorAUD) - baseFloorAUD);

      mStart = startOfMonth();                 // local start (display only)
      mEnd   = srvNext || startOfNextMonth();  // trust server for end

      // Snap display to the current target smoothly
      easeTo(targetNow());
    } catch (e) {
      console.warn("[jackpot] using fallback (no /api/jackpot):", e?.message || e);
      // fallback: just show the prorated base and tick forward
      easeTo(targetNow());
    }
  }

  /* ================= ticking ================= */
  function tick() {
    const now = Date.now();
    // rise at the base slope
    displayAUD += baseRatePerMs() * (now - lastTick);
    lastTick = now;

    // cap at current target
    const tgt = targetNow(now);
    if (displayAUD > tgt) displayAUD = tgt;

    renderAmount(displayAUD);
  }

  // Keep timers well-behaved across tab visibility changes
  document.addEventListener("visibilitychange", () => {
    lastTick = Date.now();
  });

  /* ================= admin reset ================= */
  async function ensureAdmin() {
    try {
      const chk = await fetch("/api/admin/gate/check", { credentials: "include", cache: "no-store" }).then(r => r.json());
      if (chk?.admin) return true;
    } catch {}
    const u = prompt("Admin username:");
    if (!u) return false;
    const p = prompt("Admin password:");
    if (!p) return false;
    const r = await fetch("/api/admin/gate/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username: u, password: p })
    });
    return r.ok;
  }

  async function resetJackpot() {
    try {
      const r = await fetch("/api/jackpot/reset", { method: "POST", credentials: "include" });
      if (!r.ok) throw new Error("reset failed");
      await fetchJackpotSnapshot();
      alert("Jackpot reset for this month.");
    } catch (e) {
      console.error("[jackpot] reset error:", e);
      alert("Reset failed.");
    }
  }

  async function wireReset() {
    const btn = document.getElementById("resetJackpotBtn");
    if (!btn) return;
    // Show the button; we’ll still prompt for creds if needed
    btn.style.display = "inline-block";
    btn.addEventListener("click", async () => {
      if (!(await ensureAdmin())) { alert("Admin required."); return; }
      if (!confirm("Reset this month’s jackpot? (keeps A$150 floor, clears extras)")) return;
      await resetJackpot();
    });
  }

  /* ================= boot ================= */
  document.addEventListener("DOMContentLoaded", () => {
    setSymbol("A$");            // show AUD explicitly
    mStart = startOfMonth();    // start from current month window
    mEnd   = startOfNextMonth();
    displayAUD = targetNow();   // never look frozen at 0
    renderAmount(displayAUD);
    lastTick = Date.now();

    wireReset();
    fetchJackpotSnapshot();            // initial snapshot
    setInterval(fetchJackpotSnapshot, 30_000); // refresh extras every 30s
    setInterval(tick, 200);            // animate ~5 fps
  });
})();
