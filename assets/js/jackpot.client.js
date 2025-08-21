// jackpot.client.js
// Usage in HTML:
//   <div id="jackpot" data-format="AUD ${amount.toLocaleString()}" data-refresh="15000"></div>
//   <script src="/js/jackpot.client.js" defer></script>

(function () {
  const ENDPOINT = "/api/jackpot";

  function formatAmount(num, el) {
    const f = (el?.dataset?.format || "AUD ${amount.toLocaleString()}");
    const amount = Number(num || 0);
    // very small templating
    try {
      // eslint-disable-next-line no-new-func
      return Function("amount", `return \`${f}\``)(amount);
    } catch {
      return `AUD ${amount.toLocaleString()}`;
    }
  }

  async function fetchJackpot() {
    try {
      const r = await fetch(ENDPOINT, { credentials: "same-origin" });
      if (!r.ok) throw new Error("jackpot fetch failed");
      const j = await r.json();
      return j?.jackpot || { amount: 0 };
    } catch {
      return { amount: 0 };
    }
  }

  function render(el, data) {
    if (!el) return;
    const amountText = formatAmount(data.amount, el);
    el.textContent = amountText;
    el.setAttribute("data-jackpot-amount", String(Number(data.amount || 0)));
    el.setAttribute("data-jackpot-updated", String(Date.now()));
  }

  async function tick(el) {
    const data = await fetchJackpot();
    render(el, data);
  }

  function initOne(el) {
    const refreshMs = Math.max(1000, Number(el.dataset.refresh || 15000));
    // first paint immediately
    tick(el);
    // refresh
    const t = setInterval(() => tick(el), refreshMs);
    // store handle so you can clear later if needed
    el._jackpotInterval = t;
  }

  function init() {
    // default: #jackpot; also support multiple via [data-jackpot]
    const targets = Array.from(
      document.querySelectorAll("[data-jackpot], #jackpot")
    ).filter((v, i, arr) => arr.indexOf(v) === i);

    if (targets.length === 0) return;

    targets.forEach(initOne);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
