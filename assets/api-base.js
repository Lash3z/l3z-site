// POINT FRONTEND → RENDER BACKEND
window.API_BASE = "https://YOUR-BACKEND.onrender.com";

(function (global) {
  "use strict";

  // ===== Singleton guard =====
  if (global.__L3Z_API_HELPER__) return;
  global.__L3Z_API_HELPER__ = true;

  // ===== Resolve API base (order matters) =====
  function readMetaBase() {
    try {
      var m = document.querySelector('meta[name="api-base"], meta[name="api:base"]');
      if (m && m.content) return m.content.trim();
    } catch (_) {}
    return "";
  }
  function readScriptDataBase() {
    try {
      var s = document.currentScript || document.querySelector('script[data-api-base]');
      if (s && s.dataset && s.dataset.apiBase) return String(s.dataset.apiBase || "").trim();
    } catch (_) {}
    return "";
  }
  function inferLocalDevBase() {
    try {
      var h = location.hostname, p = String(location.port || "");
      var isLocal = /^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/i.test(h);
      var devPorts = ["5173","5500","5501","5502","8080"];
      if (isLocal || devPorts.indexOf(p) >= 0) return "http://127.0.0.1:3000";
    } catch (_) {}
    return "";
  }

  // Allow CI/templating replacement if you REALLY want: "%%API_BASE%%"
  // If it's not replaced, it will include '%' and be ignored.
  var templ = "%%API_BASE%%";
  var templBase = (/%/.test(templ) ? "" : templ);

  var resolvedBase =
      (typeof global.API_BASE === "string" && global.API_BASE.trim()) ? global.API_BASE.trim() :
      (typeof global.__API_BASE === "string" && global.__API_BASE.trim()) ? global.__API_BASE.trim() :
      readMetaBase() ||
      readScriptDataBase() ||
      templBase ||
      inferLocalDevBase() ||
      ""; // same-origin (production via reverse proxy)

  // Expose & allow override at runtime
  function setBase(base) { global.API_BASE = String(base || ""); }
  setBase(resolvedBase);

  // ===== Utils =====
  function extend(target, src) {
    if (!src) return target;
    for (var k in src) if (Object.prototype.hasOwnProperty.call(src, k)) target[k] = src[k];
    return target;
  }
  function isAbsolute(url) { return /^([a-z]+:)?\/\//i.test(url); }
  function isJsonLikeCT(ct) { return !!ct && /(application|text)\/(vnd\.[^+]+\+)?json/i.test(ct); }

  function resolveUrl(path) {
    if (typeof path !== "string") path = String(path || "");
    if (isAbsolute(path)) return path;
    var base = global.API_BASE || "";
    try { return base ? new URL(path, base).toString() : path; }
    catch (_e) { return path; }
  }

  function readBody(res) {
    if (!res) return Promise.resolve(null);
    if (res.status === 204 || res.status === 205) return Promise.resolve(null);
    var ct = res && res.headers ? (res.headers.get("content-type") || "") : "";
    if (isJsonLikeCT(ct)) return res.json().catch(function(){ return null; });
    return res.text().catch(function(){ return null; });
  }

  function parseRetryAfterMs(res) {
    try{
      var ra = res && res.headers ? res.headers.get("retry-after") : null;
      if(!ra) return null;
      var n = Number(ra);
      if (!isNaN(n)) return Math.max(0, n * 1000);
      var d = Date.parse(ra);
      if (!isNaN(d)) return Math.max(0, d - Date.now());
    }catch(_){}
    return null;
  }

  function makeError(res, body, url) {
    var status = res ? res.status : 0;
    var msg = (body && (body.error || body.message)) || ("HTTP " + status);
    var err = new Error(msg);
    err.status = status;
    err.body = body || null;
    err.url = url || null;
    err.retryAfterMs = parseRetryAfterMs(res);
    return err;
  }

  // ===== Core fetch with timeout & retries =====
  function apiFetch(path, opts) {
    opts = opts || {};
    var url = resolveUrl(path);

    var headers = extend({ "Accept": "application/json, text/plain, */*" }, (opts.headers || {}));
    var init = extend({
      credentials: "include",              // for auth cookies (SameSite=None; Secure)
      method: (opts.method || "GET"),
      headers: headers,
      cache: "no-store"
    }, opts);

    // Normalize JSON body unless it's FormData/Blob/string/URLSearchParams
    if (Object.prototype.hasOwnProperty.call(init, "body")) {
      var b = init.body;
      var isFD = (typeof FormData !== "undefined") && (b instanceof FormData);
      var isBlob = (typeof Blob !== "undefined") && (b instanceof Blob);
      var isStr = (typeof b === "string");
      var isUSP = (typeof URLSearchParams !== "undefined") && (b instanceof URLSearchParams);
      var hasCT = headers && (Object.prototype.hasOwnProperty.call(headers, "Content-Type") || Object.prototype.hasOwnProperty.call(headers, "content-type"));
      if (!isFD && !isBlob && !isStr && !isUSP) {
        if (!hasCT) headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(b == null ? {} : b);
      }
    }

    var timeoutMs = Number(opts.timeoutMs || 12000);
    var ac = (typeof AbortController !== "undefined") ? new AbortController() : null;
    if (ac) init.signal = ac.signal;
    var timeoutId = (timeoutMs > 0 && ac) ? setTimeout(function(){ try{ ac.abort(); }catch(_){ } }, timeoutMs) : null;

    var attempt = 0, maxAttempts = (init.method === "GET" || init.method === "HEAD") ? (opts.retries == null ? 2 : Math.max(0, opts.retries)) : 0;

    function tryOnce() {
      return fetch(url, init).then(function(res){
        return readBody(res).then(function(body){
          var explicitFail = body && typeof body === "object" && body.ok === false;
          if (!res.ok || explicitFail) {
            if ((res.status === 429 || res.status === 503) && attempt < maxAttempts) {
              var wait = parseRetryAfterMs(res);
              if (wait == null) { var backoff = 300 * Math.pow(2, attempt); wait = Math.min(2000, backoff); }
              attempt++;
              return new Promise(function(rs){ setTimeout(rs, wait); }).then(tryOnce);
            }
            throw makeError(res, body, url);
          }
          return (body !== null && body !== undefined) ? body : { ok: true };
        });
      }).catch(function(err){
        // Network/abort: maybe retry if idempotent
        if ((err && err.name === "AbortError") || !err || err.status === 0) {
          if (attempt < maxAttempts) {
            attempt++;
            var wait = 200 * Math.pow(2, attempt-1);
            return new Promise(function(rs){ setTimeout(rs, wait); }).then(tryOnce);
          }
        }
        throw err && err.status != null ? err : makeError(null, null, url);
      }).finally(function(){
        if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
      });
    }

    return tryOnce();
  }

  // ===== Convenience methods =====
  function u(p) { return resolveUrl(p); }
  function get(p, opts) { return apiFetch(p, extend({ method: "GET" }, (opts || {}))); }
  function post(p, body, opts) { var init = extend({ method: "POST" }, (opts || {})); init.body = (body || {}); return apiFetch(p, init); }
  function put(p, body, opts)  { var init = extend({ method: "PUT"  }, (opts || {})); init.body = (body || {}); return apiFetch(p, init); }
  function del(p, opts)        { return apiFetch(p, extend({ method: "DELETE" }, (opts || {}))); }
  function upload(p, formDataOrBlob, opts) {
    var init = extend({ method: "POST" }, (opts || {}));
    init.body = formDataOrBlob;
    if (init.headers) { delete init.headers["Content-Type"]; delete init.headers["content-type"]; }
    return apiFetch(p, init);
  }
  function tryPaths(paths, init) {
    var i = 0;
    function next(err) {
      if (i >= paths.length) throw err || new Error("No paths succeeded");
      return apiFetch(paths[i++], init).catch(next);
    }
    return next();
  }
  function health() { return get("/healthz", { timeoutMs: 4000, retries: 0 }); }

  // ===== Expose =====
  global.apiFetch = apiFetch;
  global.api = {
    u: u, get: get, post: post, put: put, del: del, upload: upload,
    tryPaths: tryPaths, health: health, setBase: setBase
  };

  // Optional: log once so you know where it's pointing in prod
  try {
    var dbg = (global.API_BASE || "(same-origin)");
    if (!global.__L3Z_API_BASE_LOGGED__) {
      global.__L3Z_API_BASE_LOGGED__ = true;
      console.log("[L3Z] API_BASE →", dbg);
    }
  } catch (_){}

})(typeof window !== "undefined" ? window : this);
