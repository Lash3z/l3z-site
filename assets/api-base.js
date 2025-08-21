(function (global) {
  // Singleton guard
  if (global.__L3Z_API_HELPER__) return;
  global.__L3Z_API_HELPER__ = true;

  // Preserve any base set earlier
  global.API_BASE = global.API_BASE || "";

  function extend(target, src) {
    if (!src) return target;
    for (var k in src) if (Object.prototype.hasOwnProperty.call(src, k)) target[k] = src[k];
    return target;
  }

  function isAbsolute(url) {
    return /^([a-z]+:)?\/\//i.test(url);
  }

  function resolveUrl(path) {
    if (typeof path !== "string") path = String(path || "");
    if (isAbsolute(path)) return path;
    var base = global.API_BASE || "";
    try { return base ? new URL(path, base).toString() : path; }
    catch (e) { return path; }
  }

  function isJsonResponse(res) {
    var ct = res && res.headers ? res.headers.get("content-type") : "";
    return ct && /application\/json/i.test(ct);
  }

  function readBody(res) {
    if (!res) return Promise.resolve(null);
    if (res.status === 204 || res.status === 205) return Promise.resolve(null);
    if (isJsonResponse(res)) {
      return res.json().catch(function () { return null; });
    }
    return res.text().catch(function () { return null; });
  }

  function makeError(res, body) {
    var status = res ? res.status : 0;
    var msg = (body && (body.error || body.message)) || ("HTTP " + status);
    var err = new Error(msg);
    err.status = status;
    err.body = body || null;
    return err;
  }

  function apiFetch(path, opts) {
    opts = opts || {};
    var url = resolveUrl(path);

    // base init
    var headers = extend({ "Accept": "application/json, text/plain, */*" }, (opts.headers || {}));
    var init = extend({ credentials: "include", method: (opts.method || "GET"), headers: headers }, opts);

    // normalize body if present (JSON by default unless FormData/Blob/string)
    if (Object.prototype.hasOwnProperty.call(init, "body")) {
      var b = init.body;
      var isFD = (typeof FormData !== "undefined") && (b instanceof FormData);
      var isBlob = (typeof Blob !== "undefined") && (b instanceof Blob);
      var hasCT = headers && (Object.prototype.hasOwnProperty.call(headers, "Content-Type") ||
                              Object.prototype.hasOwnProperty.call(headers, "content-type"));
      if (!isFD && !isBlob) {
        if (!hasCT) headers["Content-Type"] = "application/json";
        if (typeof b !== "string") init.body = JSON.stringify(b || {});
      }
    }

    return fetch(url, init).then(function (res) {
      return readBody(res).then(function (body) {
        var explicitFail = body && typeof body === "object" && body.ok === false;
        if (!res.ok || explicitFail) throw makeError(res, body);
        return (body !== null && body !== undefined) ? body : { ok: true };
      });
    }, function () {
      throw makeError(null, null);
    });
  }

  function setBase(base) { global.API_BASE = String(base || ""); }
  function u(p) { return resolveUrl(p); }
  function get(p, opts) { return apiFetch(p, extend({ method: "GET" }, (opts || {}))); }
  function post(p, body, opts) {
    var init = extend({ method: "POST" }, (opts || {}));
    init.body = (body || {});
    return apiFetch(p, init);
  }

  // expose
  global.apiFetch = apiFetch;
  global.api = { u: u, get: get, post: post, setBase: setBase };

})(typeof window !== "undefined" ? window : this);
