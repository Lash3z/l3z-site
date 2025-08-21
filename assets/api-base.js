/* /assets/api-base.js  — single-origin API + helper (works on cPanel) */
(function (global) {
  "use strict";

  // --- Set API base to SAME-ORIGIN (https://yourdomain.com) ---
  // All API calls should be like api.get("/api/me") and will resolve to your cPanel domain.
  global.API_BASE = ""; // keep empty for same-origin

  // --- Guard so we don't redefine twice ---
  if (global.__L3Z_API_HELPER__) {
    try { console.log("[L3Z] API_BASE →", global.API_BASE || "(same-origin)"); } catch(_) {}
    return;
  }
  global.__L3Z_API_HELPER__ = true;

  // --- Utils ---
  function extend(t, s){ if(!s) return t; for(var k in s) if(Object.prototype.hasOwnProperty.call(s,k)) t[k]=s[k]; return t; }
  function isAbs(u){ return /^([a-z]+:)?\/\//i.test(u); }
  function isJsonCT(ct){ return !!ct && /(application|text)\/(vnd\.[^+]+\+)?json/i.test(ct); }
  function resolveUrl(p){
    if (typeof p!=="string") p=String(p||"");
    if (isAbs(p)) return p;
    var b = global.API_BASE || "";
    try { return b ? new URL(p, b).toString() : p; } catch(_) { return p; }
  }
  function readBody(res){
    if (!res) return Promise.resolve(null);
    if (res.status===204 || res.status===205) return Promise.resolve(null);
    var ct = res && res.headers ? (res.headers.get("content-type")||"") : "";
    if (isJsonCT(ct)) return res.json().catch(function(){return null;});
    return res.text().catch(function(){return null;});
  }
  function retryAfterMs(res){
    try{
      var ra = res && res.headers ? res.headers.get("retry-after") : null;
      if (!ra) return null;
      var n = Number(ra); if (!isNaN(n)) return Math.max(0, n*1000);
      var d = Date.parse(ra); if (!isNaN(d)) return Math.max(0, d-Date.now());
    }catch(_){}
    return null;
  }
  function makeErr(res, body, url){
    var s = res ? res.status : 0;
    var msg = (body && (body.error||body.message)) || ("HTTP "+s);
    var e = new Error(msg); e.status=s; e.body=body||null; e.url=url||null; e.retryAfterMs=retryAfterMs(res); return e;
  }

  // --- Core fetch with timeout + retries (GET/HEAD) ---
  function apiFetch(path, opts){
    opts = opts || {};
    var url = resolveUrl(path);
    var headers = extend({"Accept":"application/json, text/plain, */*"}, (opts.headers||{}));
    var init = extend({
      credentials: "include",   // for auth cookies
      method: (opts.method||"GET"),
      headers: headers,
      cache: "no-store"
    }, opts);

    if (Object.prototype.hasOwnProperty.call(init,"body")){
      var b = init.body;
      var isFD = (typeof FormData!=="undefined") && (b instanceof FormData);
      var isBlob = (typeof Blob!=="undefined") && (b instanceof Blob);
      var isStr = (typeof b==="string");
      var isUSP = (typeof URLSearchParams!=="undefined") && (b instanceof URLSearchParams);
      var hasCT = headers && (Object.prototype.hasOwnProperty.call(headers,"Content-Type") || Object.prototype.hasOwnProperty.call(headers,"content-type"));
      if (!isFD && !isBlob && !isStr && !isUSP){
        if (!hasCT) headers["Content-Type"]="application/json";
        init.body = JSON.stringify(b==null?{}:b);
      }
    }

    var timeoutMs = Number(opts.timeoutMs||12000);
    var ac = (typeof AbortController!=="undefined") ? new AbortController() : null;
    if (ac) init.signal = ac.signal;
    var toId = (timeoutMs>0 && ac) ? setTimeout(function(){ try{ ac.abort(); }catch(_){ } }, timeoutMs) : null;

    var attempt = 0, maxA = (init.method==="GET"||init.method==="HEAD") ? (opts.retries==null?2:Math.max(0,opts.retries)) : 0;

    function once(){
      return fetch(url, init).then(function(res){
        return readBody(res).then(function(body){
          var explicitFail = body && typeof body==="object" && body.ok===false;
          if (!res.ok || explicitFail){
            if ((res.status===429||res.status===503) && attempt<maxA){
              var wait = retryAfterMs(res); if (wait==null){ var back=300*Math.pow(2,attempt); wait=Math.min(2000,back); }
              attempt++; return new Promise(function(rs){ setTimeout(rs, wait); }).then(once);
            }
            throw makeErr(res, body, url);
          }
          return (body!==null && body!==undefined) ? body : {ok:true};
        });
      }).catch(function(err){
        if ((err && err.name==="AbortError") || !err || err.status===0){
          if (attempt<maxA){ attempt++; var w=200*Math.pow(2,attempt-1); return new Promise(function(rs){ setTimeout(rs,w); }).then(once); }
        }
        throw err && err.status!=null ? err : makeErr(null,null,url);
      }).finally(function(){ if (toId){ clearTimeout(toId); toId=null; }});
    }

    return once();
  }

  function setBase(b){ global.API_BASE = String(b||""); }
  function u(p){ return resolveUrl(p); }
  function get(p,o){ return apiFetch(p, extend({method:"GET"}, (o||{}))); }
  function post(p,b,o){ var i=extend({method:"POST"},(o||{})); i.body=(b||{}); return apiFetch(p,i); }
  function put(p,b,o){ var i=extend({method:"PUT"}, (o||{})); i.body=(b||{}); return apiFetch(p,i); }
  function del(p,o){ return apiFetch(p, extend({method:"DELETE"}, (o||{}))); }
  function upload(p,formOrBlob,o){ var i=extend({method:"POST"},(o||{})); i.body=formOrBlob; if(i.headers){ delete i.headers["Content-Type"]; delete i.headers["content-type"]; } return apiFetch(p,i); }
  function tryPaths(paths, init){ var i=0; function next(err){ if(i>=paths.length) throw err||new Error("No paths succeeded"); return apiFetch(paths[i++], init).catch(next); } return next(); }
  function health(){ return get("/api/healthz",{timeoutMs:4000,retries:0}); }

  global.apiFetch = apiFetch;
  global.api = { u, get, post, put, del, upload, tryPaths, health, setBase };

  try { console.log("[L3Z] API_BASE →", global.API_BASE || "(same-origin)"); } catch(_){}
})(typeof window!=="undefined"?window:this);
