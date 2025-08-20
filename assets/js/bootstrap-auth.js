/* L3Z — Canonical Auth Bootstrap (single source of truth)
   Depends on: /assets/api-base.js (window.api)

   - Calls /api/me, stores window.__USER
   - Paints #whoami, #walletBalance, cookie badges if present
   - Adds body classes: auth-ok | auth-missing
   - Public API: window.session { getUser, isAuthed, refresh, onChange }
   - Optional: window.AUTH_REFRESH_MS (e.g. 30000), window.AUTH_DEBUG=true
*/
(function(){
  const DEBUG = !!window.AUTH_DEBUG;
  const REFRESH_MS = Number.isFinite(+window.AUTH_REFRESH_MS) ? +window.AUTH_REFRESH_MS : 0;

  function waitForApi(ms=2000){
    return new Promise((resolve,reject)=>{
      if (window.api) return resolve();
      const t0 = Date.now();
      const t = setInterval(()=>{ if (window.api){ clearInterval(t); resolve(); }
        else if (Date.now()-t0>ms){ clearInterval(t); reject(new Error("api-base not loaded")); }},25);
    });
  }

  const SEL = {
    username: ['#whoami','[data-auth="username"]'],
    balance:  ['#walletBalance','[data-auth="balance"]'],
    cookie:   ['#cookieState','#cookieState2','[data-auth="cookie"]'],
  };
  const qAll = (arr)=> arr.flatMap(sel => Array.from(document.querySelectorAll(sel)));
  const els = { username:()=>qAll(SEL.username), balance:()=>qAll(SEL.balance), cookie:()=>qAll(SEL.cookie) };
  const setText=(nodes,txt)=>nodes.forEach(n=>{ try{ n.textContent=String(txt??""); }catch{} });
  const setCookieState=(ok)=> setText(els.cookie(), ok?"cookie: ok":"cookie: missing");
  const coerceBalance=(u)=> Number((u&&u.wallet&&u.wallet.balance) ?? u?.balance ?? u?.lbx ?? 0);

  let _user=null; const subs=new Set(); const notify=()=>subs.forEach(fn=>{ try{fn(_user);}catch{} });

  async function fetchMe(){ const me = await window.api.get("/api/me"); if(!me||!me.user) throw new Error("not_logged_in"); return me.user; }

  function paint(){
    const authed=!!_user;
    document.body.classList.toggle("auth-ok",authed);
    document.body.classList.toggle("auth-missing",!authed);
    if(!authed){ setText(els.username(),"(not logged in)"); setText(els.balance(),"0 LBX"); setCookieState(false); return; }
    setText(els.username(), _user.username || "—");
    setText(els.balance(), `${coerceBalance(_user).toLocaleString()} LBX`);
    setCookieState(true);
  }

  async function refresh(){
    try{
      const u = await fetchMe(); _user=u; window.__USER=u; paint(); notify(); if(DEBUG) console.log("[auth] refreshed",u.username); return u;
    }catch(e){
      _user=null; window.__USER=null; paint(); if(DEBUG) console.warn("[auth] refresh failed", e?.message||e); return null;
    }
  }

  window.session = {
    getUser: ()=>_user,
    isAuthed: ()=>!!_user,
    refresh,
    onChange: (fn)=>{ if(typeof fn==="function") subs.add(fn); return ()=>subs.delete(fn); }
  };

  async function boot(){
    try{ await waitForApi(); }catch(e){ if(DEBUG) console.warn("[auth] api wait failed", e.message); }
    await refresh();
    if(REFRESH_MS>0) setInterval(refresh, REFRESH_MS);
    window.addEventListener("auth:refresh", refresh);
    window.addEventListener("storage", ev=>{ if(ev.key==="lash3z_last_user") refresh(); });
  }
  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
