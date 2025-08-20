// backend/models/wallet/wallet.service.js (ESM)
// Safe, idempotent wallet ops for LBX/points.
// - Username normalized to lowercase
// - No ledger trimming/removal (ever)
// - balance and lbx kept in sync
// - Optional idempotent `ref` to avoid double-apply

import { mutate, readOnly, nowISO, nextId } from "../../lib/store.js";

const norm = (u) => String(u || "").trim().toLowerCase();

function ensureUser(db, usernameRaw) {
  const username = norm(usernameRaw);
  let u = db.users.find(x => norm(x.username) === username);
  if (!u) {
    u = {
      username,
      points: 0,
      lbx: 0,
      wallet: { balance: 0, ledger: [] },
      createdAt: nowISO(),
    };
    db.users.push(u);
  }
  // Make sure structures exist
  if (!u.wallet) u.wallet = { balance: 0, ledger: [] };
  if (!Array.isArray(u.wallet.ledger)) u.wallet.ledger = [];
  if (typeof u.wallet.balance !== "number") u.wallet.balance = Number(u.wallet.balance) || 0;
  if (typeof u.lbx !== "number") u.lbx = Number(u.lbx) || u.wallet.balance || 0;

  // Keep legacy points aligned if used anywhere else
  if (typeof u.points !== "number") u.points = 0;

  // One true source is wallet.balance; mirror to lbx
  if (u.lbx !== u.wallet.balance) {
    u.lbx = u.wallet.balance;
  }

  return u;
}

function exposeBalance(u) {
  const balance = Number(u?.wallet?.balance ?? 0);
  return { balance, lbx: balance };
}

/**
 * Read current balance (returns { ok, balance, lbx })
 */
export async function getBalance(username) {
  return readOnly(db => {
    const u = db.users.find(x => norm(x.username) === norm(username));
    return { ok: true, ...(exposeBalance(u)) };
  });
}

/**
 * Read ledger (latest first). Never removes on write; this is just a view.
 */
export async function getLedger(username, limit = 50) {
  return readOnly(db => {
    const u = db.users.find(x => norm(x.username) === norm(username));
    const ledger = u?.wallet?.ledger || [];
    // view only — do NOT mutate/trim the stored ledger
    const lim = Math.max(1, Math.min(1000, Number(limit) || 50));
    return { ok: true, ledger: ledger.slice(-lim).reverse() };
  });
}

/**
 * Internal change applicator (idempotent by optional `ref`)
 * - delta can be +/-
 * - never allows resulting balance < 0 (returns { ok:false, error:"insufficient_funds" })
 * - writes a ledger row with ts, delta, reason, ref
 */
function applyChange(db, usernameRaw, deltaRaw, reason = "adjust", ref = null) {
  const username = norm(usernameRaw);
  const delta = Number(deltaRaw);
  if (!username || !Number.isFinite(delta)) {
    return { ok: false, error: "bad_input" };
  }

  const u = ensureUser(db, username);

  // Idempotency: if ref provided and already in ledger, return current state
  if (ref) {
    const already = u.wallet.ledger.find(e => e && e.ref && String(e.ref) === String(ref));
    if (already) {
      return { ok: true, ...(exposeBalance(u)), idempotent: true };
    }
  }

  const current = Number(u.wallet.balance || 0);
  const next = current + delta;

  if (next < 0) {
    return { ok: false, error: "insufficient_funds" };
  }

  u.wallet.balance = next;
  u.lbx = next;            // keep mirror in sync
  // leave u.points alone unless you purposely use it elsewhere

  u.wallet.ledger.push({
    id: nextId(db, "txn"),
    ts: nowISO(),
    delta,
    reason: String(reason || (delta >= 0 ? "credit" : "debit")),
    ref: ref || null,
    balanceAfter: next,
  });

  return { ok: true, ...(exposeBalance(u)) };
}

/**
 * Adjust can be +/-.
 * reason can be string or options object: { reason, ref }
 */
export async function adjust(username, delta, reason = "adjust") {
  const opts = (reason && typeof reason === "object") ? reason : { reason };
  return mutate(db => applyChange(db, username, delta, opts.reason || "adjust", opts.ref || null));
}

/**
 * Credit: adds absolute(amount). Optional options object as 3rd param: { reason, ref }
 */
export async function credit(username, amount, reason = "credit") {
  const amt = Math.abs(Number(amount) || 0);
  const opts = (reason && typeof reason === "object") ? reason : { reason };
  return mutate(db => applyChange(db, username, amt, opts.reason || "credit", opts.ref || null));
}

/**
 * Debit: subtracts absolute(amount) but will not go below 0.
 * Optional options object as 3rd param: { reason, ref }
 */
export async function debit(username, amount, reason = "debit") {
  const amt = Math.abs(Number(amount) || 0);
  const opts = (reason && typeof reason === "object") ? reason : { reason };
  return mutate(db => applyChange(db, username, -amt, opts.reason || "debit", opts.ref || null));
}

/**
 * Optional explicit sync apply (never removes):
 * Use when ingesting a server event stream; pass a stable `ref` to avoid replays.
 */
export async function syncApply(username, delta, meta = {}) {
  const { reason = "sync", ref = meta?.ref || null } = meta || {};
  return mutate(db => applyChange(db, username, delta, reason, ref));
}

export default { getBalance, getLedger, adjust, credit, debit, syncApply };
