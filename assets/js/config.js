// /assets/js/config.js
// Single source of truth for your API origin.
// All pages/scripts read window.API_BASE (used by /assets/api-base.js).
//
// ✅ How to use:
//   1) Set RENDER_API to your Render service URL (no trailing slash).
//   2) Include THIS file before /assets/api-base.js on every page.
//
// Example <head> order:
//   <script src="/assets/js/config.js"></script>
//   <script src="/assets/api-base.js"></script>

(() => {
  // ===== EDIT THIS: your deployed API base (https://xxx.onrender.com)
  const RENDER_API = "https://YOUR-API-SERVICE.onrender.com";

  // Optional: allow override via <meta name="api-base" content="https://...">
  const meta = document.querySelector('meta[name="api-base"]');
  const metaBase = meta?.getAttribute?.("content")?.trim();

  // If you keep frontend + API on SAME origin in prod, leave empty ("")
  // and deploy both under the same domain/subdomain.
  const derived = metaBase || RENDER_API || "";

  // Expose ONLY if not already defined (so env injects can win)
  if (typeof window.API_BASE === "undefined") {
    Object.defineProperty(window, "API_BASE", {
      value: (derived || "").replace(/\/+$/, ""), // strip trailing slash
      writable: false,
      enumerable: true,
    });
  }

  // Tiny sanity log (visible once, harmless)
  try {
    const base = window.API_BASE || "";
    console.log(`[L3Z] API_BASE = ${base || "(same-origin)"}`);
  } catch {}
})();
