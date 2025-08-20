// /assets/api-base.js — unified API helper for live & local
// Provides:
//   - window.API_BASE (optional, set per page if API is on another origin)
//   - window.apiFetch(path, options)  // always sends cookies
//   - window.api.{u,get,post,put,del} // convenience JSON wrappers
//
// Usage (same-origin API):
//   <script src="/assets/api-base.js"></script>
//
// Usage (cross-origin API):
//   <script>window.API_BASE = "https://api.your-domain.com";</script>
//   <script src="/assets/api-base.js"></script>
//
// All requests use credentials:"include" so your auth cookie flows cross-origin
// as long as CORS is correctly allowlisted on the server.

(() => {
  // Allow pages to override API base; default is same-origin.
  if (typeof window.API_BASE !== "string") window.API_BASE = "";

  function join(base, p) {
    if (!base) return p;
    if (/^https?:\/\//i.test(p)) return p;
    const b = base.endsWith("/") ? base.slice(0, -1) : base;
    const s = p.startsWith("/") ? p : `/${p}`;
    return `${b}${s}`;
  }

  const u = (p) => join(window.API_BASE, p);

  function isFormData(x) {
    return typeof FormData !== "undefined" && x instanceof FormData;
  }

  async function apiFetch(path, opts = {}) {
    const url = u(path);
    const init = {
      method: opts.method || "GET",
      credentials: "include",        // include cookies for auth
      cache: opts.cache || "no-store",
      headers: { ...(opts.headers || {}) },
      body: opts.body,
      signal: opts.signal,
    };

    // Auto-JSON encode plain objects
    if (init.body && typeof init.body === "object" && !isFormData(init.body)) {
      if (!init.headers["Content-Type"]) init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(init.body);
    }

    const res = await fetch(url, init);

    const ct = (res.headers.get("content-type") || "").toLowerCase();
    const isJson = ct.includes("application/json");
    const data = isJson ? await res.json().catch(() => ({})) : await res.text().catch(() => "");

    if (!res.ok) {
      // Normalize common API error shapes
      const msg =
        (isJson && (data.error || data.message || data.detail)) ||
        (typeof data === "string" && data) ||
        `HTTP ${res.status}`;
      const err = new Error(String(msg));
      err.status = res.status;
      err.payload = data;
      throw err;
    }

    return data;
  }

  // Convenience wrappers
  const get  = (p)       => apiFetch(p, { method: "GET" });
  const post = (p, body) => apiFetch(p, { method: "POST", body });
  const put  = (p, body) => apiFetch(p, { method: "PUT", body });
  const del  = (p, body) => apiFetch(p, { method: "DELETE", body });

  // Expose globally
  window.apiFetch = apiFetch;
  window.api = { u, get, post, put, del };
})();
