// /assets/js/bootstrap-auth.js — bootstraps session & profile for HUD
// Depends on /assets/api-base.js being loaded first
// Paints user info, balance, login state across pages.

(async () => {
  const $ = (s, r=document) => r.querySelector(s);
  const say = (el, msg, ok) => {
    if (!el) return;
    el.textContent = msg || "";
    el.className = (ok === undefined) ? "muted" : (ok ? "ok" : "err");
  };

  const userEl = $("#whoami");
  const balEl  = $("#walletBalance");

  try {
    // Try fetch /api/me with credentials
    const me = await window.api.get("/api/me");

    if (!me?.ok || !me.user) throw new Error("not_logged_in");

    const u = me.user;
    const balance = Number(
      (u && u.wallet && u.wallet.balance) ??
      u.balance ??
      u.lbx ??
      0
    );

    if (userEl) userEl.textContent = u.username;
    if (balEl)  balEl.textContent  = `${balance.toLocaleString()} LBX`;

    document.body.classList.add("auth-ok");
  } catch (e) {
    if (userEl) userEl.textContent = "(not logged in)";
    if (balEl)  balEl.textContent  = "0 LBX";
    document.body.classList.add("auth-missing");
    console.warn("[auth] bootstrap failed", e);
  }
})();
