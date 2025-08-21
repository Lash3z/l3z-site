// assets/js/bootstrap-auth.js
// Sync the server session into localStorage + patch common UI.
// Safe for prod and VS Code Live Server; resilient to missing routes.

(function () {
  "use strict";

  // ---------- tiny helper layer ----------
  const hasApi = typeof window.apiFetch === "function";
  const fetchJSON = async (path, init = {}) => {
    if (hasApi) return window.apiFetch(path, init);
    // Fallback if api-base.js didn't load yet
    const base =
      typeof window.__API_BASE === "string" && window.__API_BASE
        ? window.__API_BASE
        : (location.port === "5501" ? "http://127.0.0.1:3000" : "");
    const res = await fetch(base + path, {
      credentials: "include",
      cache: "no-store",
      ...init,
      headers: {
        Accept: "application/json, text/plain, */*",
        "Content-Type": "application/json",
        ...(init.headers || {}),
      },
    });
    const ct = res.headers.get("content-type") || "";
    const body = ct.includes("json") ? await res.json().catch(() => null) : await res.text().catch(() => null);
    if (!res.ok || (body && body.ok === false)) {
      const err = new Error((body && (body.error || body.message)) || ("HTTP " + res.status));
      err.status = res.status;
      err.body = body;
      throw err;
    }
    return body ?? { ok: true };
  };

  const up = (s) => String(s || "").trim().toUpperCase();
  const onlyUpgradeNumber = (el, value) => {
    if (!el) return;
    const v = Math.max(0, Math.floor(Number(value) || 0));
    const cur = Math.max(0, Math.floor(Number(String(el.textContent).replace(/[^\d.-]/g, "")) || 0));
    if (cur !== 0 && v === 0) return; // don't downgrade a non-zero to 0
    el.textContent = String(v);
  };

  // Pick a best-guess local username before hitting the server
  const pickLocalUser = () => {
    try {
      const qs = new URLSearchParams(location.search).get("viewer");
      if (qs) return up(qs);
    } catch {}
    try {
      const sess = JSON.parse(localStorage.getItem("l3z:session") || "null");
      if (sess && sess.user) return up(sess.user);
    } catch {}
    try {
      const prof = JSON.parse(localStorage.getItem("l3z:user") || "null");
      if (prof && prof.username) return up(prof.username);
    } catch {}
    const legacy = localStorage.getItem("user:username");
    if (legacy) return up(legacy);
    const last = localStorage.getItem("lash3z_last_user");
    if (last) return up(last);
    return "PLAYER";
  };

  // ---------- main ----------
  async function refreshSession() {
    // Start with a local guess; server can override
    let username = pickLocalUser();
    let balance = 0;

    // Try the API in a robust order; tolerate any that are not present
    // 1) viewer profile (preferred when available)
    try {
      const me = await fetchJSON("/api/viewer/me");
      if (me && typeof me === "object") {
        if (me.username) username = up(me.username);
        if (me.wallet && typeof me.wallet.balance === "number") balance = me.wallet.balance;
      }
    } catch {}

    // 2) generic /api/me (some backends expose lbx here)
    if (!balance) {
      try {
        const me2 = await fetchJSON("/api/me");
        if (me2 && typeof me2 === "object") {
          if (me2.username || me2.user || me2.name) username = up(me2.username || me2.user || me2.name);
          const lbx =
            (me2.user && typeof me2.user.lbx === "number" && me2.user.lbx) ||
            (typeof me2.lbx === "number" && me2.lbx);
          if (typeof lbx === "number") balance = lbx;
        }
      } catch {}
    }

    // 3) dedicated wallet endpoints
    if (!balance) {
      try {
        const w1 = await fetchJSON("/api/wallet/balance");
        if (w1 && typeof w1.balance === "number") balance = w1.balance;
      } catch {}
    }
    if (!balance) {
      try {
        const w2 = await fetchJSON("/api/wallet/me?viewer=" + encodeURIComponent(username));
        if (w2 && w2.wallet && typeof w2.wallet.balance === "number") balance = w2.wallet.balance;
      } catch {}
    }

    // Normalize
    balance = Math.max(0, Math.floor(Number(balance) || 0));
    username = up(username || "PLAYER");

    // ---------- persist to legacy keys so old pages “just work” ----------
    try {
      // Session-ish mirrors
      localStorage.setItem("auth:username", username);
      localStorage.setItem("lash3z_last_user", username);
      localStorage.setItem("user:name", username);
      localStorage.setItem("user:username", username);
      localStorage.setItem("l3z:session", JSON.stringify({ user: username, ts: Date.now() }));
      localStorage.setItem("l3z:user", JSON.stringify({ username }));

      // Wallet mirrors (string + object)
      localStorage.setItem("lbx_balance", String(balance));
      localStorage.setItem("wallet:balance", String(balance));
      localStorage.setItem("lbx_wallet", JSON.stringify({ user: username, balance, ts: Date.now() }));
    } catch {}

    // ---------- patch common UI places (when present) ----------
    const setTxt = (sel, txt) => {
      const n = document.querySelector(sel);
      if (n) { n.textContent = txt; n.title = txt; }
    };
    setTxt("#usernameDisplay", "Welcome, " + username);
    setTxt("#ubName", username);
    onlyUpgradeNumber(document.querySelector("#ubBal"), balance);

    // Generic data-bux badges
    document.querySelectorAll("[data-bux]").forEach((el) => (el.textContent = String(balance)));

    // expose for console debugging
    window.session = { name: username, balance };

    // Emit a hook other scripts can listen to
    try {
      window.dispatchEvent(new CustomEvent("l3z:session:refreshed", { detail: { username, balance } }));
    } catch {}
  }

  // Run on DOM ready; refresh again when tab regains focus
  document.addEventListener("DOMContentLoaded", refreshSession);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshSession(); });

  // Allow manual refresh from console / other scripts
  window.refreshSession = refreshSession;
})();
