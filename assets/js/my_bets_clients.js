// /assets/js/my_bets_client.js
(() => {
  const U = (window.L3Z?.username) || localStorage.getItem("user:username") || "";
  const all = JSON.parse(localStorage.getItem("sb:tickets") || "[]");
  const tickets = all.filter(t => !t.user || t.user === U).sort((a,b) => b.at - a.at);

  // optional badges
  const total = document.getElementById("totalBets");
  if (total) total.textContent = tickets.length;

  // “Live now” (last 48h)
  const liveHost = document.getElementById("liveList");
  if (liveHost) {
    const since = Date.now() - 48*3600*1000;
    const recent = tickets.filter(t => t.at >= since);
    liveHost.innerHTML = recent.length ? recent.map(t => {
      const pick = t.mode === "single"
        ? (t.leg?.selLabel || t.leg?.guess || t.leg?.label || "-")
        : `${(t.legs||[]).length} legs`;
      return `<div>${new Date(t.at).toLocaleString()} — ${t.mode.toUpperCase()} — ${pick} — <strong>${t.stake||0} LBX</strong> @ ${(t.odds||1).toFixed(2)}×</div>`;
    }).join("") : "<em>No fresh bets in the last 48 hours.</em>";
  }

  // History table
  const tbody = document.getElementById("historyBody");
  if (!tbody) return;
  tbody.innerHTML = tickets.slice(0, 200).map(t => {
    const market  = t.mode === "single" ? (t.leg?.label || t.leg?.mtype || "-") : "MULTI";
    const pick    = t.mode === "single" ? (t.leg?.selLabel || t.leg?.guess || "-")
                                        : (t.legs||[]).map(x => x.selLabel || x.guess || x.label).join(" + ");
    const section = t.leg?.section?.toUpperCase?.() || "-";
    const pot     = (Number(t.stake||0) * Number(t.odds||1)) || 0;
    return `<tr>
      <td>${new Date(t.at).toLocaleString()}</td>
      <td>${t.mode}</td>
      <td>${section}</td>
      <td>${market}</td>
      <td>${pick}</td>
      <td class="num">${t.stake||0}</td>
      <td class="num">${(t.odds||1).toFixed(2)}×</td>
      <td class="num">${pot.toFixed(0)}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="8">No bets yet.</td></tr>`;
})();
