/* L3Z — Minimal API client (cookies + base URL + nice errors)
   Usage:
     await api.get("/api/me")
     await api.post("/api/auth/login", { username, password })

   Optional (cross-origin API):
     <script>window.API_BASE="https://api.your-domain.com";</script>
*/
(function(){
  const BASE = String(window.API_BASE || "").replace(/\/+$/,"");

  function toURL(path){
    if (!path) return BASE || "/";
    if (/^https?:\/\//i.test(path)) return path;
    if (!BASE) return path;
    return `${BASE}${path.startsWith("/") ? path : "/"+path}`;
  }

  async function handle(res){
    const type = res.headers.get("content-type") || "";
    const parse = async () => {
      if (type.includes("application/json")) { try { return await res.json(); } catch { return {}; } }
      const t = await res.text().catch(()=> ""); return t || {};
    };
    if (res.ok) return parse();

    const payload = await parse();
    const msg = (payload && (payload.error || payload.detail || payload.message)) || `HTTP ${res.status}`;
    const err = new Error(typeof msg === "string" ? msg : "Request failed");
    err.status = res.status; err.payload = payload; throw err;
  }

  async function req(method, path, body, opts){
    const url = toURL(path);
    const init = { method, credentials:"include", cache:"no-store", headers:{ "Accept":"application/json" }, ...opts };
    if (body !== undefined && body !== null) {
      if (body instanceof FormData) init.body = body;
      else { init.headers["Content-Type"]="application/json"; init.body = JSON.stringify(body); }
    }
    const res = await fetch(url, init); return handle(res);
  }

  const api = {
    base: BASE, url: toURL,
    get:(p,o)=>req("GET",p,undefined,o),
    post:(p,b,o)=>req("POST",p,b,o),
    put:(p,b,o)=>req("PUT",p,b,o),
    patch:(p,b,o)=>req("PATCH",p,b,o),
    del:(p,b,o)=>req("DELETE",p,b,o),
  };
  window.api = api;
})();
