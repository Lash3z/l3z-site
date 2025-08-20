// /assets/api-base.js
// Minimal, hardened fetch wrapper used across HUD + Admin pages.
// - Cookies included by default (JWT in HttpOnly cookie)
// - JSON by default; graceful text fallback
// - Timeouts, error normalization, querystring helper
// - Emits "api:unauthorized" on 401 so pages can redirect

(() => {
  if (window.api) return; // idempotent

  const API_BASE = (window.API_BASE || "").replace(/\/+$/, ""); // e.g. "" (same origin) or "https://api.example.com"

  const DEFAULTS = {
    timeoutMs: 15000,
    credentials: "include",
    cache: "no-store",
  };

  function qs(params) {
    if (!params) return "";
    const sp = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v === undefined || v === null) return;
      if (Array.isArray(v)) v.forEach(x => sp.append(k, String(x)));
      else sp.set(k, String(v));
    });
    const s = sp.toString();
    return s ? `?${s}` : "";
  }

  async function _fetch(path, { method = "GET", headers, body, timeoutMs, signal, ...rest } = {}) {
    const url = (path.startsWith("http://") || path.startsWith("https://"))
      ? path
      : `${API_BASE}${path}`;

    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(new DOMException("Timeout", "AbortError")), timeoutMs || DEFAULTS.timeoutMs);

    const opts = {
      method,
      credentials: DEFAULTS.credentials,
      cache: DEFAULTS.cache,
      signal: signal || ctl.signal,
      headers: {
        Accept: "application/json, text/plain;q=0.6, */*;q=0.3",
        ...headers,
      },
      ...rest,
    };

    if (body !== undefined && body !== null) {
      if (typeof body === "object" && !(body instanceof FormData) && !(body instanceof Blob)) {
        opts.headers["Content-Type"] = opts.headers["Content-Type"] || "application/json";
        opts.body = JSON.stringify(body);
      } else {
        opts.body = body;
      }
    }

    let res;
    try {
      res = await fetch(url, opts);
    } catch (err) {
      clearTimeout(to);
      throw enrichError(err, { kind: "network", url, method });
    }
    clearTimeout(to);

    const ct = res.headers.get("content-type") || "";
    let parsed, raw;

    try {
      if (ct.includes("application/json")) {
        parsed = await res.json();
      } else {
        raw = await res.text();
        try { parsed = JSON.parse(raw); } catch { parsed = { ok: res.ok, data: raw }; }
      }
    } catch (err) {
      // Bad JSON from server; surface as readable
      throw enrichError(err, { kind: "decode", url, method, status: res.status });
    }

    if (!res.ok) {
      const err = new Error(normalizeMsg(parsed) || `HTTP ${res.status}`);
      err.status = res.status;
      err.code = parsed?.error || parsed?.code;
      err.detail = parsed?.detail || parsed?.message || parsed;
      err.url = url;
      err.method = method;

      if (res.status === 401) {
        // allow pages to attach a handler to kick to login
        window.dispatchEvent(new CustomEvent("api:unauthorized", { detail: { url, method } }));
      }
      throw err;
    }

    return parsed;
  }

  function normalizeMsg(j) {
    if (!j) return "";
    // prefer known keys; replace underscores for UX
    const m = j.message || j.error || j.detail || "";
    return typeof m === "string" ? m.replace(/_/g, " ") : "";
  }

  function enrichError(err, extra) {
    try {
      Object.assign(err, extra || {});
    } catch {}
    return err;
  }

  // Public API
  const api = {
    base: API_BASE,
    qs,

    async get(path, params) {
      const url = params ? `${path}${qs(params)}` : path;
      return _fetch(url, { method: "GET" });
    },

    async post(path, body) {
      return _fetch(path, { method: "POST", body });
    },

    async put(path, body) {
      return _fetch(path, { method: "PUT", body });
    },

    async patch(path, body) {
      return _fetch(path, { method: "PATCH", body });
    },

    async del(path, body) {
      return _fetch(path, { method: "DELETE", body });
    },

    // Fire-and-forget tracker (never throws)
    async track(path, payload) {
      try { await _fetch(path, { method: "POST", body: payload }); } catch {}
    },

    // Helper to wrap handlers with standard error UX
    async guard(fn, onError) {
      try { return await fn(); }
      catch (e) {
        if (typeof onError === "function") onError(e);
        else console.warn("[api] error:", e);
        return null;
      }
    }
  };

  Object.defineProperty(window, "api", { value: api, writable: false, enumerable: true });
})();
