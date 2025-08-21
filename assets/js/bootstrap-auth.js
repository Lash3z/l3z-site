// assets/js/bootstrap-auth.js
// Runs on every page, syncs the server session into localStorage + patches UI.

(function () {
  async function refreshSession() {
    try {
      const r = await fetch("/api/wallet/me", {
        credentials: "include",
        cache: "no-store",
      });
      if (!r.ok) throw new Error("not logged in");
      const me = await r.json();

      const name =
        String(me.username || me.user || me.name || "").toUpperCase() || "PLAYER";
      const balance = Number(me.balance ?? me.lbx ?? 0);

      // Write to several legacy keys so *any* old page can see it
      localStorage.setItem("auth:username", name);
      localStorage.setItem("lash3z_last_user", name);
      localStorage.setItem("user:name", name);

      localStorage.setItem("lbx_balance", String(balance));
      localStorage.setItem("wallet:balance", String(balance));
      localStorage.setItem(
        "lbx_wallet",
        JSON.stringify({ user: name, balance, ts: Date.now() })
      );

      // Optional: patch common placeholders if present
      const u = document.querySelector("#usernameDisplay");
      if (u) u.textContent = "Welcome, " + name;

      const buxBadges = document.querySelectorAll("[data-bux]");
      buxBadges.forEach((el) => (el.textContent = String(balance)));

      // Expose for manual refresh from console if needed
      window.session = { name, balance, raw: me };
    } catch (e) {
      // leave defaults in place
      // console.debug("[bootstrap-auth] no session:", e?.message || e);
    }
  }

  document.addEventListener("DOMContentLoaded", refreshSession);
  window.refreshSession = refreshSession;
})();
