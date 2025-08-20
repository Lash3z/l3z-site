/* L3Z — Canonical Auth Bootstrap
   Depends on: /assets/api-base.js (window.api)
   What it does:
     - Calls /api/me, stores user on window.__USER
     - Paints username (#whoami) and balance (#walletBalance) if present
     - Paints cookie badges if present (#cookieState, #cookieState2, [data-auth="cookie"])
     - Adds body classes: auth-ok | auth-missing
     - Exposes lightweight session API on window.session:
         session.getUser()     -> current user or null
         session.isAuthed()    -> boolean
         session.refresh()     -> re-fetch /api/me and repaint
         session.onChange(fn)  -> subscribe to user changes
     - Optional knobs:
         window.AUTH_REFRESH_MS = 0 (default; no polling). Set e.g. 30000 for 30s refresh.
         window.AUTH_DEBUG = true to log.
*/

(function(){
  const DEBUG = !!window.AUTH_DEBUG;
  const REFRESH_MS = Number.isFinite(+window.AUTH_REFRESH_MS) ? +window.AUTH_REFRESH_MS : 0;

  // In case api-base hasn’t loaded yet, wait briefly.
  function waitForApi(ms=2000){
    return new Promise((resolve, reject)=>{
      if (window.api) return resolve();
      const started = Date.now();
      const t = setInterval(()=>{
        if (window.api) { clearInterval(t); resolve(); }
        else if (Date.now() - started > ms) { clearInterval(t); reject(new Error("api-base not loaded")); }
      }, 25);
    });
  }

  const SEL = {
    username: ['#whoami','[data-auth="username"]'],
    balance:  ['#walletBalance','[data-auth="balance"]'],
    cookie:   ['#cookieState','#cookieState2','[data-auth="cookie"]'],
  };

  const qAll = (arr)=> arr.flatMap(sel => Array.from(document.querySelectorAll(sel)));

  const els = {
    username: () => qAll(SEL.username),
    balance:  () => qAll(SEL.balance),
    cookie:   () => qAll(SEL.cookie),
  };

  function setText(nodes, text){
    nodes.forEach(n => { try { n.textContent = String(text ?? ""); } catch{} });
  }
  function setCookieState(ok){
    const txt = ok ? "cookie: ok" : "cookie: missing";
    setText(els.cookie(), txt);
  }

  function coerceBalance(u){
    return Number(
      (u && u.wallet && u.wallet.balance) ??
      u?.balance ??
      u?.lbx ??
      0
    );
  }

  let _user = null;
  const subs = new Set();
  function notify(){ subs.forEach(fn => { try{ fn(_user); }catch{} }); }

  async function fetchMe(){
    const me = await window.api.get("/api/me");  // { ok, user }
    if (!me || !me.user) throw new Error("not_logged_in");
    return me.user;
  }

  function paint(){
    const isAuthed = !!_user;
    document.body.classList.toggle("auth-ok", isAuthed);
    document.body.classList.toggle("auth-missing", !isAuthed);

    if (!isAuthed){
      setText(els.username(), "(not logged in)");
      setText(els.balance(),  "0 LBX");
      setCookieState(false);
      return;
    }

    const bal = coerceBalance(_user);
    setText(els.username(), _user.username || "—");
    setText(els.balance(),  `${bal.toLocaleString()} LBX`);
    setCookieState(true);
  }

  async function refresh(){
    try{
      const u = await fetchMe();
      _user = u;
      window.__USER = u;
      paint();
      notify();
      if (DEBUG) console.log("[auth] refreshed", u.username);
      return u;
    }catch(err){
      _user = null;
      window.__USER = null;
      paint();
      if (DEBUG) console.warn("[auth] refresh failed", err?.message || err);
      return null;
    }
  }

  // Public session API
  const session = {
    getUser:  ()=> _user,
    isAuthed: ()=> !!_user,
    refresh,
    onChange: (fn)=> { if (typeof fn === "function") subs.add(fn); return ()=> subs.delete(fn); },
  };
  window.session = session;

  // Kick off once DOM is ready and api is present
  async function boot(){
    try { await waitForApi(); } catch(e){ if (DEBUG) console.warn("[auth] api wait failed", e.message); }
    await refresh();

    // Optional polling (disabled by default)
    if (REFRESH_MS && REFRESH_MS > 0){
      setInterval(refresh, REFRESH_MS);
    }

    // Listen for manual triggers from any page:
    window.addEventListener("auth:refresh", refresh);

    // If other tabs/pages change user (e.g., login page sets last_user), you can listen here.
    window.addEventListener("storage", (ev)=>{
      if (ev.key === "lash3z_last_user") refresh();
    });
  }

  if (document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
