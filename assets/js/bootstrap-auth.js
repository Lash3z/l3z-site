// /assets/js/bootstrap-auth.js
// Bootstraps session state across pages.
// Requires: /assets/api-base.js to be loaded first.
// - Paints username + LBX balance wherever present
// - Adds body classes: .auth-ok / .auth-missing
// - Handles logout button (#logout) if present
// - Optional Kick link/unlink widgets if present
// - Redirects on 401 using data-login-url or sensible default

(() => {
  if (window.__BOOTSTRAP_AUTH_INSTALLED__) return;
  window.__BOOTSTRAP_AUTH_INSTALLED__ = true;

  const $  = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

  const fmtLBX = n => `${Number(n || 0).toLocaleString()} LBX`;
  const asNum  = v => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

  // allow pages to override login destination
  const LOGIN_URL =
    document.body.getAttribute("data-login-url")
    || (location.pathname.includes("/admin") ? "/admin/login.html" : "/login.html");

  // paint helpers
  function setText(el, text) { if (el) el.textContent = text; }
  function toggle(els, show) { $$(els).forEach(el => { el.style.display = show ? "" : "none"; }); }

  // global-ish state
  let currentUser = null;
  let currentLBX  = 0;

  // -- session fetchers -------------------------------------------------------

  async function fetchMe() {
    try {
      const j = await api.get("/api/me");
      if (!j?.ok || !j.user) throw new Error("not_logged_in");
      currentUser = j.user;
      // try wallet endpoint for freshest LBX; fallback to user.lbx
      try {
        const w = await api.get("/api/wallet");
        currentLBX = asNum(w?.lbx);
      } catch {
        currentLBX = asNum(j.user?.wallet?.balance ?? j.user?.balance ?? j.user?.lbx);
      }
      return true;
    } catch {
      currentUser = null;
      currentLBX  = 0;
      return false;
    }
  }

  // -- painters ---------------------------------------------------------------

  function paintAuth() {
    const authed = !!currentUser;
    document.body.classList.toggle("auth-ok", authed);
    document.body.classList.toggle("auth-missing", !authed);

    // Common IDs
    setText($("#whoami"), authed ? currentUser.username : "(not logged in)");
    setText($("#walletBalance"), fmtLBX(currentLBX));

    // Data-binds: <span data-bind="username">, data-bind="lbx"
    $$( '[data-bind="username"]' ).forEach(el => setText(el, authed ? currentUser.username : ""));
    $$( '[data-bind="role"]'     ).forEach(el => setText(el, authed ? (currentUser.role || "user") : ""));
    $$( '[data-bind="lbx"]'      ).forEach(el => setText(el, fmtLBX(currentLBX)));

    // Conditional blocks
    toggle('[data-if-auth]',  authed);
    toggle('[data-if-guest]', !authed);

    // Admin badge if present
    const who = $("#who");
    if (who) {
      setText(who, authed ? `${(currentUser.role === "admin" ? "admin" : "user")}: ${currentUser.username}` : "admin: (not logged in)");
    }
  }

  // -- Kick linking (optional UI bits) ---------------------------------------
  // Expected server routes (gracefully ignored if not present):
  //   GET  /api/social/kick/status -> { ok, linked, profile? }
  //   POST /api/social/kick/link_start -> { ok, url }  (redirect user to auth)
  //   POST /api/social/kick/unlink -> { ok }
  async function refreshKick() {
    const badge  = $("#kickStatus");
    const linkBtn= $("#kickLink");
    const unBtn  = $("#kickUnlink");

    if (!badge && !linkBtn && !unBtn) return; // page doesn't care

    try {
      const j = await api.get("/api/social/kick/status");
      if (j?.linked) {
        setText(badge, `Kick: linked${j?.profile?.username ? ` (@${j.profile.username})` : ""}`);
        if (linkBtn)  linkBtn.style.display = "none";
        if (unBtn)    unBtn.style.display   = "";
      } else {
        setText(badge, "Kick: not linked");
        if (linkBtn)  linkBtn.style.display = "";
        if (unBtn)    unBtn.style.display   = "none";
      }
    } catch {
      setText(badge, "Kick: unavailable");
      if (linkBtn) linkBtn.style.display = "";
      if (unBtn)   unBtn.style.display   = "none";
    }
  }

  async function startKickLink() {
    try {
      const j = await api.post("/api/social/kick/link_start", {});
      if (j?.url) {
        // Go complete linking; server should bounce back to site.
        location.href = j.url;
      }
    } catch (e) {
      console.warn("[kick] link_start failed", e);
      // as a fallback, try a GET redirect if server supports it
      location.href = "/api/social/kick/link_start";
    }
  }

  async function unlinkKick() {
    try {
      await api.post("/api/social/kick/unlink", {});
    } catch {}
    refreshKick();
  }

  // -- events ----------------------------------------------------------------

  // Redirect any page on unauthorized API calls
  window.addEventListener("api:unauthorized", () => {
    // don’t loop if we’re already at the login page
    if (!location.pathname.endsWith(LOGIN_URL)) {
      location.href = LOGIN_URL;
    }
  });

  // Logout if a #logout button exists
  $("#logout")?.addEventListener("click", async () => {
    try { await api.post("/api/auth/logout", {}); } catch {}
    // hard redirect to login; if page sets data-login-url, respect it
    location.href = LOGIN_URL;
  });

  // Optional kick buttons
  $("#kickLink")?.addEventListener("click", startKickLink);
  $("#kickUnlink")?.addEventListener("click", unlinkKick);

  // Listen for pages hinting a balance change and repaint quickly
  window.addEventListener("wallet:refresh", async () => {
    try {
      const w = await api.get("/api/wallet");
      currentLBX = asNum(w?.lbx);
      paintAuth();
    } catch {}
  });

  // Allow pushing a known balance without refetch
  window.addEventListener("wallet:update", (e) => {
    if (e?.detail?.lbx != null) {
      currentLBX = asNum(e.detail.lbx);
      paintAuth();
    }
  });

  // -- boot ------------------------------------------------------------------

  (async function boot() {
    await fetchMe();
    paintAuth();
    await refreshKick();
  })();

  // expose read-only snapshot for other scripts
  Object.defineProperty(window, "sessionUser", {
    get() { return currentUser; }
  });
  Object.defineProperty(window, "sessionLBX", {
    get() { return currentLBX; }
  });
})();
