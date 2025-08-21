// assets/api-base.js
(() => {
  // The server injects window.API_BASE ("" by default) before this script.
  if (typeof window.API_BASE !== "string") window.API_BASE = "";

  // Minimal helper so client code can call your API safely from any host.
  window.apiFetch = async (path, opts = {}) => {
    const url = `${window.API_BASE}${path}`;
    const init = {
      credentials: "include",
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      ...opts,
    };
    return fetch(url, init);
  };
})();
