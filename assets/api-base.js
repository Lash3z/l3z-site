<script>
// /assets/api-base.js
(function () {
  window.API_BASE = window.API_BASE || ""; // set this on each page if API is on a different origin
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
</script>
