// /assets/js/l3z_wallet_bridge.js
(() => {
  const LOGIN = "/pages/dashboard/home/login.html";

  // --- helpers ---
  const up = s => (s || "").toString().trim().toUpperCase();
  const now = () => Date.now();
  const sget = k => { try { return JSON.parse(localStorage.getItem(k) || "null"); } catch { return null; } };
  const sset = (k,v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} };

  // --- session / username (same one Profile uses) ---
  const sess = sget("l3z:session");
  let username = up(sess?.user ||
                    localStorage.getItem("auth:username") ||
                    localStorage.getItem("lash3z_last_user") || "");
  if (!username) {
    const back = encodeURIComponent(location.pathname + location.search + location.hash);
    location.replace(`${LOGIN}?redirect=${back}`);
    throw 0;
  }
  localStorage.setItem("user:username", username);
  localStorage.setItem("lash3z_last_user", username);

  // --- wallet keys ---
  const WKEY = u => `lbx:wallet:${up(u)}`;
  const LKEY = u => `lbx:ledger:${up(u)}`;

  function ensureWallet(u) {
    let w = sget(WKEY(u));
    if (!w) {
      w = { balance: 50, created: now(), lastDaily: 0 };
      sset(WKEY(u), w);
      sset(LKEY(u), [{ ts: now(), delta: +50, reason: "WELCOME_BONUS", balance: 50 }]);
    }
    return w;
  }
  function balance() { return Number((sget(WKEY(username))?.balance) || 0); }

  // --- paint common UI bits (works with multiple selectors) ---
  function paint() {
    // username
    document.querySelectorAll('#who,[data-username],.username-display')
      .forEach(el => el.textContent =
        (el.id === "who" || el.classList.contains("username-display"))
          ? `Welcome, ${username}` : username);

    // bux
    const b = balance().toLocaleString(undefined, { maximumFractionDigits: 0 });
    document.querySelectorAll('#bal,[data-bux],.bux-amount,.wallet-bux')
      .forEach(el => el.dataset.raw === "1" ? (el.textContent = b)
                                            : (el.textContent = `🪙 ${b} BUX`));
  }

  ensureWallet(username);
  document.addEventListener("DOMContentLoaded", paint);
  window.addEventListener("storage", e => {
    if (e.key === WKEY(username) || e.key === LKEY(username)) paint();
  });

  // expose for other scripts
  window.L3Z = { username, WKEY, LKEY, ensureWallet, balance, sget, sset };
})();
