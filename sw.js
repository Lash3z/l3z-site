/* /sw.js — cache static only, bypass /api */
const CACHE_NAME = "l3z-static-v1";
const STATIC_GLOBS = [
  "/", "/index.html",
  "/assets/api-base.js",
  // Add other core files you want pre-cached:
  // "/assets/styles.css", "/assets/logo.png",
];

self.addEventListener("install", (evt) => {
  evt.waitUntil(
    caches.open(CACHE_NAME).then((c) => c.addAll(STATIC_GLOBS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (evt) => {
  evt.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (evt) => {
  const url = new URL(evt.request.url);
  // Never cache API, admin, or POSTs
  if (url.pathname.startsWith("/api") || evt.request.method !== "GET") {
    return; // let network handle
  }
  evt.respondWith(
    caches.match(evt.request).then((hit) => {
      return hit || fetch(evt.request).then((res) => {
        // Cache successful GETs for later
        const copy = res.clone();
        caches.open(CACHE_NAME).then((c) => c.put(evt.request, copy)).catch(()=>{});
        return res;
      }).catch(() => hit); // fall back to cache if offline
    })
  );
});
