// /assets/js/api-base.js
// Small helper so the client can call your API consistently.
// server.js injects <script>window.API_BASE="...";</script> + this file into every HTML.
(function () {
  window.API_BASE = window.API_BASE || "";
  const u = (p) => (window.API_BASE || "") + p;
  async function get(p) {
    const res = await fetch(u(p), { credentials: "include" });
    const ct = res.headers.get("content-type") || "";
    return ct.includes("application/json") ? res.json() : res.text();
  }
  async function post(p, body) {
    const res = await fetch(u(p), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(body || {}),
    });
    const ct = res.headers.get("content-type") || "";
    return ct.includes("application/json") ? res.json() : res.text();
  }
  window.api = { u, get, post };
})();
