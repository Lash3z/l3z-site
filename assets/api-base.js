// /assets/api-base.js  — sets API base for same-origin (cPanel)
(function (global) {
  if (global.__API_BASE_SET__) return;
  global.__API_BASE_SET__ = true;

  // Same-origin: frontend and API share https://yourdomain.com
  // All client calls like apiFetch("/api/whatever") will hit the same domain.
  global.API_BASE = ""; // keep empty for same-origin

  try { console.log("[L3Z] API_BASE →", global.API_BASE || "(same-origin)"); } catch (_) {}
})(typeof window !== "undefined" ? window : this);
