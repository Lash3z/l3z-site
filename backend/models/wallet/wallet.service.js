// backend/models/wallet/wallet.service.js (ESM)
import { mutate, readOnly, nowISO, nextId } from "../../lib/store.js";

function ensureUser(db, username) {
  let u = db.users.find(x => x.username === username);
  if (!u) {
    u = {
      username,
      points: 0,
      wallet: { balance: 0, ledger: [] },
      createdAt: nowISO()
    };
    db.users.push(u);
  }
  if (!u.wallet) u.wallet = { balance: 0, ledger: [] };
  if (!Array.isArray(u.wallet.ledger)) u.wallet.ledger = [];
  if (typeof u.wallet.balance !== "number") u.wallet.balance = 0;
  return u;
}

export async function getBalance(username) {
  return readOnly(db => {
    const u = db.users.find(x => x.username === username);
    return { ok: true, balance: u?.wallet?.balance ?? 0 };
  });
}

export async function getLedger(username, limit = 50) {
  return readOnly(db => {
    const u = db.users.find(x => x.username === username);
    const ledger = u?.wallet?.ledger || [];
    return { ok: true, ledger: ledger.slice(-limit).reverse() };
  });
}

export async function adjust(username, delta, reason = "adjust") {
  if (!username || typeof delta !== "number" || Number.isNaN(delta)) {
    return { ok: false, error: "bad_input" };
  }
  return mutate(db => {
    const u = ensureUser(db, username);
    u.wallet.balance += delta;
    u.wallet.ledger.push({ ts: nowISO(), delta, reason, ref: nextId(db, "txn") });
    return { ok: true, balance: u.wallet.balance };
  });
}

export async function credit(username, amount, reason = "credit") {
  const amt = Math.abs(Number(amount) || 0);
  return adjust(username, amt, reason);
}

export async function debit(username, amount, reason = "debit") {
  const amt = Math.abs(Number(amount) || 0);
  return adjust(username, -amt, reason);
}

export default { getBalance, getLedger, adjust, credit, debit };
