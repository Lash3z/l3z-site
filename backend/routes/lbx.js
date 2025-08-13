// backend/routes/lbx.js (ESM)
import express from "express";
import mongoose from "mongoose";

const router = express.Router();

// ---------- helpers ----------
const DAY = 24 * 60 * 60 * 1000;
const up = (s) => (s || "").toString().trim().toUpperCase();
const now = () => Date.now();
const allowedPkgs = new Set([5, 10, 15, 20, 25, 30]);

const hasMongo = !!(mongoose?.connection && mongoose.connection.readyState > 0);

// ---------- Mongo models (if available) ----------
let Order, Wallet, Ledger;

if (hasMongo) {
  const OrderSchema = new mongoose.Schema(
    {
      user: { type: String, required: true, index: true, uppercase: true, trim: true },
      amount: { type: Number, required: true, min: 1 },
      usd: { type: Number, required: true, min: 0 },
      asset: { type: String, required: true },
      address: { type: String, default: "" },
      ref: { type: String, default: "" },
      txid: { type: String, default: "" },
      status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending", index: true },
      ts: { type: Number, default: () => Date.now(), index: true },
      note: { type: String, default: "" },
      approvedAt: { type: Number, default: 0 },
      approvedBy: { type: String, default: "" },
      rejectedAt: { type: Number, default: 0 },
      rejectedBy: { type: String, default: "" },
    },
    { collection: "lbx_orders" }
  );

  const WalletSchema = new mongoose.Schema(
    {
      user: { type: String, required: true, unique: true, uppercase: true, trim: true },
      balance: { type: Number, default: 0 },
      lastDaily: { type: Number, default: 0 },
      created: { type: Number, default: () => Date.now() },
    },
    { collection: "lbx_wallets" }
  );

  const LedgerSchema = new mongoose.Schema(
    {
      user: { type: String, required: true, index: true, uppercase: true, trim: true },
      ts: { type: Number, default: () => Date.now(), index: true },
      delta: { type: Number, required: true },
      reason: { type: String, default: "" },
      balance: { type: Number, required: true },
    },
    { collection: "lbx_ledger" }
  );

  Order = mongoose.models.LbxOrder || mongoose.model("LbxOrder", OrderSchema);
  Wallet = mongoose.models.LbxWallet || mongoose.model("LbxWallet", WalletSchema);
  Ledger = mongoose.models.LbxLedger || mongoose.model("LbxLedger", LedgerSchema);
}

// ---------- In-memory fallback ----------
const mem = {
  orders: [],            // {id,user,amount,usd,asset,address,ref,txid,status,ts,note,approvedAt,approvedBy,...}
  wallets: new Map(),    // user -> {balance, lastDaily, created}
  ledger: [],            // {user,ts,delta,reason,balance}
};
const newId = (p = "ORD") => `${p}-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;

async function memGetOrders(filter = {}) {
  let arr = mem.orders.slice();
  if (filter.status && filter.status !== "all") arr = arr.filter((o) => o.status === filter.status);
  if (filter.since) arr = arr.filter((o) => o.ts >= filter.since);
  if (filter.user) arr = arr.filter((o) => up(o.user) === up(filter.user));
  return arr.sort((a, b) => b.ts - a.ts);
}

async function memCreateOrder(data) {
  const o = { id: newId(), status: "pending", ts: now(), note: "", approvedAt: 0, approvedBy: "", rejectedAt: 0, rejectedBy: "", ...data };
  mem.orders.push(o);
  return o;
}

async function memFindOrder(id) {
  return mem.orders.find((o) => o.id === id);
}

async function memSaveOrder(o) {
  const i = mem.orders.findIndex((x) => x.id === o.id);
  if (i >= 0) mem.orders[i] = o;
  return o;
}

function memGetWallet(user) {
  user = up(user);
  if (!mem.wallets.has(user)) mem.wallets.set(user, { balance: 0, lastDaily: 0, created: now() });
  return mem.wallets.get(user);
}

function memSetWallet(user, w) {
  mem.wallets.set(up(user), w);
}

function memPushLedger(user, delta, reason) {
  const w = memGetWallet(user);
  w.balance = +(w.balance || 0) + +delta;
  memSetWallet(user, w);
  const row = { user: up(user), ts: now(), delta: +delta, reason: reason || "", balance: w.balance };
  mem.ledger.push(row);
  return { wallet: w, ledger: row };
}

async function sumUserInWindow(user, windowStart, { includePending = true } = {}) {
  user = up(user);
  if (hasMongo) {
    const match = { user, ts: { $gte: windowStart } };
    if (!includePending) match.status = "approved";
    else match.status = { $in: ["pending", "approved"] };
    const rows = await Order.find(match).select("amount").lean();
    return rows.reduce((a, r) => a + (+r.amount || 0), 0);
  } else {
    const rows = mem.orders.filter(
      (o) =>
        up(o.user) === user &&
        o.ts >= windowStart &&
        (includePending ? (o.status === "pending" || o.status === "approved") : o.status === "approved")
    );
    return rows.reduce((a, r) => a + (+r.amount || 0), 0);
  }
}

async function creditWallet(user, amount, reason) {
  user = up(user);
  if (hasMongo) {
    const w = await Wallet.findOneAndUpdate(
      { user },
      { $setOnInsert: { created: now(), lastDaily: 0 }, $inc: { balance: +amount } },
      { upsert: true, new: true }
    );
    await Ledger.create({ user, ts: now(), delta: +amount, reason: reason || "RECHARGE", balance: w.balance });
    return w;
  } else {
    return memPushLedger(user, +amount, reason).wallet;
  }
}

// ---------- Routes ----------

// Create order
router.post("/lbx/orders", async (req, res) => {
  try {
    const { user, amount, usd, asset, address = "", ref = "", txid = "" } = req.body || {};
    const U = up(user);
    if (!U) return res.status(400).json({ ok: false, error: "user_required" });
    if (!allowedPkgs.has(+amount)) return res.status(400).json({ ok: false, error: "invalid_package" });
    if (!asset) return res.status(400).json({ ok: false, error: "asset_required" });

    // 30 LBX / 24h cap (pending + approved)
    const used = await sumUserInWindow(U, now() - DAY, { includePending: true });
    if (used + +amount > 30) return res.status(400).json({ ok: false, error: "daily_cap_exceeded", used, requested: +amount });

    let order;
    if (hasMongo) {
      order = await Order.create({ user: U, amount: +amount, usd: +usd || 0, asset, address, ref, txid, status: "pending", ts: now() });
    } else {
      order = await memCreateOrder({ user: U, amount: +amount, usd: +usd || 0, asset, address, ref, txid });
    }
    res.json({ ok: true, order });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

// List orders
router.get("/lbx/orders", async (req, res) => {
  try {
    const status = (req.query.status || "pending").toLowerCase();
    const qStatus = ["pending", "approved", "rejected", "all"].includes(status) ? status : "pending";
    let orders;
    if (hasMongo) {
      const filter = qStatus === "all" ? {} : { status: qStatus };
      orders = await Order.find(filter).sort({ ts: -1 }).limit(1000).lean();
    } else {
      orders = await memGetOrders({ status: qStatus });
    }
    res.json(orders);
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

// Approve order (credits wallet)
router.post("/lbx/orders/:id/approve", async (req, res) => {
  try {
    const { note = "", force = false } = req.body || {};
    const id = req.params.id;

    let order;
    if (hasMongo) order = await Order.findById(id);
    else order = await memFindOrder(id);

    if (!order) return res.status(404).json({ ok: false, error: "not_found" });
    if (order.status !== "pending") return res.status(400).json({ ok: false, error: "not_pending" });

    if (!force) {
      const usedApproved = await sumUserInWindow(order.user, now() - DAY, { includePending: false });
      if (usedApproved + +order.amount > 30)
        return res.status(400).json({ ok: false, error: "daily_cap_exceeded_on_approve", usedApproved, requested: +order.amount });
    }

    // mark approved
    order.status = "approved";
    order.approvedAt = now();
    order.approvedBy = "ADMIN";
    order.note = note || "";

    if (hasMongo) await order.save();
    else await memSaveOrder(order);

    // credit wallet + ledger
    const wallet = await creditWallet(order.user, +order.amount, `RECHARGE:CRYPTO #${hasMongo ? order._id : order.id}`);

    res.json({ ok: true, order, wallet });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

// Reject order
router.post("/lbx/orders/:id/reject", async (req, res) => {
  try {
    const { note = "" } = req.body || {};
    const id = req.params.id;

    let order;
    if (hasMongo) order = await Order.findById(id);
    else order = await memFindOrder(id);

    if (!order) return res.status(404).json({ ok: false, error: "not_found" });
    if (order.status !== "pending") return res.status(400).json({ ok: false, error: "not_pending" });

    order.status = "rejected";
    order.rejectedAt = now();
    order.rejectedBy = "ADMIN";
    order.note = note || "";

    if (hasMongo) await order.save();
    else await memSaveOrder(order);

    res.json({ ok: true, order });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

// Wallet: credit (admin tool)
router.post("/wallet/credit", async (req, res) => {
  try {
    const { user, amount, reason = "ADMIN_ADJUST" } = req.body || {};
    if (!user || !amount) return res.status(400).json({ ok: false, error: "user_and_amount_required" });
    const w = await creditWallet(user, +amount, reason);
    res.json({ ok: true, wallet: hasMongo ? { user: w.user, balance: w.balance, lastDaily: w.lastDaily } : w });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

// Wallet: get by user (with last 50 ledger rows)
router.get("/wallet/:user", async (req, res) => {
  try {
    const U = up(req.params.user);
    if (hasMongo) {
      const w = await Wallet.findOne({ user: U }).lean();
      const L = await (Ledger.find({ user: U }).sort({ ts: -1 }).limit(50).lean());
      res.json({ ok: true, wallet: w || { user: U, balance: 0, lastDaily: 0 }, ledger: L || [] });
    } else {
      const w = memGetWallet(U);
      const L = mem.ledger.filter((r) => up(r.user) === U).sort((a, b) => b.ts - a.ts).slice(0, 50);
      res.json({ ok: true, wallet: { user: U, ...w }, ledger: L });
    }
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

export default router;
