(function () {
  // Temporary no-op raffle stub. Replace with real implementation.
  window.l3zRaffle = window.l3zRaffle || {
    init() {},
    enter: async function () { return { ok: true, stub: true }; },
    status: async function () { return { ok: true, entries: [] }; }
  };
})();
