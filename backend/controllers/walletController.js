import { mutate, readOnly, nowISO, nextId } from "../lib/store.js";

function ensureUser(db, username) {
  let u = db.users.find(x => x.username === username);
  if (!u) {
    u = {
      username,
      points: 0,
      wallet: {
        balance: 50,
        ledger: [{ ts: nowISO(), delta: 50, reason: "signup bonus", ref: nextId(db, "txn") }]
      },
      createdAt: nowISO()
    };
    db.users.push(u);
  }
  return u;
}

export async function getWallet(req, res) {
  const { username } = req.params;
  if (!username) return res.status(400).json({ ok: false, error: "missing_username" });
  const out = await mutate(db => {
    const u = ensureUser(db, username);
    return { ok: true, username: u.username, balance: u.wallet.balance, points: u.points, ledger: u.wallet.ledger.slice(-50) };
  });
  res.json(out);
}

export async function spend(req, res) {
  const { username, amount, reason } = req.body || {};
  if (!username || typeof amount !== "number" || amount <= 0) return res.status(400).json({ ok: false, error: "bad_input" });
  const out = await mutate(db => {
    const u = ensureUser(db, username);
    if (u.wallet.balance < amount) return { ok: false, error: "insufficient_funds" };
    u.wallet.balance -= amount;
    u.wallet.ledger.push({ ts: nowISO(), delta: -amount, reason: reason || "spend", ref: nextId(db, "txn") });
    return { ok: true, balance: u.wallet.balance };
  });
  res.status(out.ok ? 200 : 400).json(out);
}

export async function credit(req, res) {
  const { username, amount, reason } = req.body || {};
  if (!username || typeof amount !== "number" || amount <= 0) return res.status(400).json({ ok: false, error: "bad_input" });
  const out = await mutate(db => {
    const u = ensureUser(db, username);
    u.wallet.balance += amount;
    u.wallet.ledger.push({ ts: nowISO(), delta: amount, reason: reason || "credit", ref: nextId(db, "txn") });
    return { ok: true, balance: u.wallet.balance };
  });
  res.json(out);
}

export async function adjustAdmin(req, res) {
  const { username, delta, reason } = req.body || {};
  if (!username || typeof delta !== "number") return res.status(400).json({ ok: false, error: "bad_input" });
  const out = await mutate(db => {
    const u = ensureUser(db, username);
    u.wallet.balance += delta;
    u.wallet.ledger.push({ ts: nowISO(), delta, reason: reason || "admin-adjust", ref: nextId(db, "txn") });
    return { ok: true, balance: u.wallet.balance };
  });
  res.json(out);
}
