import { mutate, nowISO } from "../lib/store.js";

export async function walletBulkAdjust(req, res) {
  const { adjustments } = req.body || {};
  if (!Array.isArray(adjustments)) return res.status(400).json({ ok: false, error: "bad_input" });

  const out = await mutate(db => {
    const results = [];
    for (const a of adjustments) {
      const { username, delta = 0, reason = "bulk" } = a || {};
      if (!username || typeof delta !== "number") continue;

      let u = db.users.find(x => x.username === username);
      if (!u) {
        u = { username, points: 0, wallet: { balance: 0, ledger: [] }, createdAt: nowISO() };
        db.users.push(u);
      }
      u.wallet.balance += delta;
      u.wallet.ledger.push({ ts: nowISO(), delta, reason });
      results.push({ username: u.username, balance: u.wallet.balance });
    }
    return { ok: true, results };
  });

  res.json(out);
}
