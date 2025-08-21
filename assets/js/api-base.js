// assets/api-base.js
(() => {
  // ---------- Base resolution ----------
  // Respect any explicitly injected base first.
  const inferredBase = (() => {
    if (typeof window.__API_BASE === "string" && window.__API_BASE) return window.__API_BASE;
    // When using VS Code Live Server (usually :5501), call the Node API on :3000
    try {
      if (location.port === "5501") return "http://127.0.0.1:3000";
    } catch (_) {}
    // Production: same-origin
    return "";
  })();

  if (typeof window.API_BASE !== "string") window.API_BASE = inferredBase;
  if (!window.API_BASE) window.API_BASE = inferredBase; // fill if empty

  // ---------- Utils ----------
  const isAbsolute = (u) => /^([a-z]+:)?\/\//i.test(u);
  const resolveUrl = (path) => {
    if (typeof path !== "string") path = String(path || "");
    if (isAbsolute(path)) return path;
    const base = window.API_BASE || "";
    try { return base ? new URL(path, base).toString() : path; }
    catch { return path; }
  };
  const isJsonCT = (ct) => !!ct && /(application|text)\/(vnd\.[^+]+\+)?json/i.test(ct);
  const readBody = async (res) => {
    if (!res) return null;
    if (res.status === 204 || res.status === 205) return null;
    const ct = res.headers.get("content-type") || "";
    if (isJsonCT(ct)) {
      try { return await res.json(); } catch { return null; }
    }
    try { return await res.text(); } catch { return null; }
  };
  const makeError = (res, body, url) => {
    const status = res ? res.status : 0;
    const msg = (body && (body.error || body.message)) || `HTTP ${status}`;
    const err = new Error(msg);
    err.status = status;
    err.body = body || null;
    err.url = url || null;
    return err;
  };

  // ---------- Core fetch (timeout, JSON, errors) ----------
  async function coreFetch(path, opts = {}) {
    const url = resolveUrl(path);

    const headers = {
      Accept: "application/json, text/plain, */*",
      ...(opts.headers || {})
    };

    const init = {
      credentials: "include",
      cache: "no-store",
      method: opts.method || "GET",
      headers,
      ...opts
    };

    // Normalize JSON body unless FormData/Blob/string/URLSearchParams
    if (Object.prototype.hasOwnProperty.call(init, "body")) {
      const b = init.body;
      const isFD   = typeof FormData !== "undefined" && b instanceof FormData;
      const isBlob = typeof Blob !== "undefined" && b instanceof Blob;
      const isStr  = typeof b === "string";
      const isUSP  = typeof URLSearchParams !== "undefined" && b instanceof URLSearchParams;
      const hasCT  = "Content-Type" in headers || "content-type" in headers;
      if (!isFD && !isBlob && !isStr && !isUSP) {
        if (!hasCT) headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(b ?? {});
      }
    }

    // Timeout via AbortController
    const timeoutMs = Number(opts.timeoutMs || 10000);
    const ac = typeof AbortController !== "undefined" ? new AbortController() : null;
    if (ac) init.signal = ac.signal;
    const timer = (timeoutMs > 0 && ac) ? setTimeout(() => { try { ac.abort(); } catch {} }, timeoutMs) : null;

    try {
      const res = await fetch(url, init);
      const body = await readBody(res);
      const explicitFail = body && typeof body === "object" && body.ok === false;
      if (!res.ok || explicitFail) throw makeError(res, body, url);
      // Return parsed body if present, else {ok:true}
      return body ?? { ok: true };
    } catch (e) {
      if (e && e.name === "AbortError") throw makeError(null, { error: "Request timed out" }, url);
      if (e && e.status != null) throw e;
      throw makeError(null, null, url);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  // ---------- Public surface ----------
  function setBase(base) { window.API_BASE = String(base || ""); }
  const get  = (p, o) => coreFetch(p, { ...(o||{}), method: "GET" });
  const post = (p, b, o) => coreFetch(p, { ...(o||{}), method: "POST", body: b });
  const put  = (p, b, o) => coreFetch(p, { ...(o||{}), method: "PUT",  body: b });
  const del  = (p, o)    => coreFetch(p, { ...(o||{}), method: "DELETE" });
  const upload = (p, formDataOrBlob, o) => {
    const hdrs = { ...(o?.headers || {}) };
    // Let browser set multipart boundary / binary type
    delete hdrs["Content-Type"]; delete hdrs["content-type"];
    return coreFetch(p, { ...(o||{}), method: "POST", headers: hdrs, body: formDataOrBlob });
  };
  const health = () => get("/healthz", { timeoutMs: 4000 });

  // Backwards compatibility:
  // - window.apiFetch returns parsed JSON (or throws).
  // - window.api exposes helper methods.
  window.apiFetch = coreFetch;
  window.api = { get, post, put, del, upload, health, setBase, u: resolveUrl };
})();
