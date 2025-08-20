// /assets/api-base.js — tiny fetch wrapper with diagnostics.
// Credentials-on by default; logs every request/response when ?diag=1
// or localStorage['l3z:debug-http']="1" or window.DEBUG_HTTP=1.

(() => {
  const has = (k) => new URLSearchParams(location.search).has(k);
  const DEBUG = has("diag") || localStorage.getItem("l3z:debug-http") === "1" || window.DEBUG_HTTP === 1;

  async function fetchJson(method, url, body) {
    const trace = (crypto.randomUUID?.() || Math.random().toString(36).slice(2));
    const headers = { "Accept": "application/json", "x-trace-id": trace };
    const opts = { method, credentials: "include", headers };

    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }

    if (DEBUG) console.log("[api]", method, url, { body, trace });

    const res = await fetch(url, opts);
    const isJson = (res.headers.get("content-type") || "").includes("application/json");
    const data = isJson ? (await res.json().catch(() => ({}))) : {};

    if (DEBUG) console.log("[api<-]", res.status, url, data, { trace });

    if (!res.ok) {
      const err = new Error(data?.error || `HTTP ${res.status}`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  window.api = {
    get:  (url)        => fetchJson("GET", url),
    post: (url, body)  => fetchJson("POST", url, body),
    put:  (url, body)  => fetchJson("PUT", url, body),
    del:  (url, body)  => fetchJson("DELETE", url, body),
  };
})();
