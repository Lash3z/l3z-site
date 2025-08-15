// backend/routes/wallet.js (ESM)
import express from "express";
import mongoose from "mongoose";

const router = express.Router();
const mongoUp = () => mongoose?.connection?.readyState === 1;
const ALLOW_MEMORY_FALLBACK = String(process.env.ALLOW_MEMORY_FALLBACK || "").toLowerCase() === "true";

/* --- Model (safe-define) --- */
let Wallet;
try {
  const schema = new mongoose.Schema(
    {
      username: { type: String, unique: true, index: true },
      balance:  { type: Number, default: 0 },
      updated:  { type: Date,   default: () => new Date() },
    },
    { versionKey: false, collection: "wallets" }
  );
  Wallet = mongoose.models.Wallet || mongoose.model("Wallet", schema);
} catch {}

/* --- Memory fallback for local-only dev --- */
const mem = new Map(); // USER -> { balance, updated }

/* --- helpers --- */
const up = s => (s||"").toString().trim().toUpperCase();
async function getOrCreate(username) {
  const user = up(username);
  if (!user) return null;

  if (mongoUp() && Wallet) {
    let doc = await Wallet.findOne({ username: user }).lean();
    if (!doc) {
      await Wallet.updateOne(
        { username: user },
        { $setOnInsert: { username: user, balance: 0, updated: new Date() } },
        { upsert: true }
      );
      doc = await Wallet.findOne({ username: user }).lean();
    }
    return { username: doc.username, balance: Number(doc.balance||0), updated: doc.updated };
  }

  if (!ALLOW_MEMORY_FALLBACK) return null;
  const cur = mem.get(user) || { balance: 0, updated: new Date() };
  mem.set(user, cur);
  return { username: user, balance: cur.balance, updated: cur.updated };
}

async function writeDelta(username, delta) {
  const user = up(username);
  const n = Number(delta||0);
  if (!user || !Number.isFinite(n)) return null;

  if (mongoUp() && Wallet) {
    const doc = await Wallet.findOneAndUpdate(
      { username: user },
      { $inc: { balance: n }, $set: { updated: new Date() } },
      { upsert: true, new: true }
    ).lean();
    return { username: doc.username, balance: Number(doc.balance||0), updated: doc.updated };
  }

  if (!ALLOW_MEMORY_FALLBACK) return null;
  const cur = mem.get(user) || { balance: 0, updated: new Date() };
  cur.balance = Number(cur.balance||0) + n;
  cur.updated = new Date();
  mem.set(user, cur);
  return { username: user, balance: cur.balance, updated: cur.updated };
}

/* --- Routes --- */

// GET /api/wallet/balance?user=LASH3Z
router.get("/balance", async (req, res) => {
  const user = up(req.query.user || "");
  if (!user) return res.status(400).json({ ok:false, error:"bad_user" });

  const rec = await getOrCreate(user);
  if (!rec) return res.status(503).json({ ok:false, error:"store_offline" });

  res.setHeader("X-Store", mongoUp() ? "mongo" : (ALLOW_MEMORY_FALLBACK ? "memory" : "offline"));
  res.json({ ok:true, username: rec.username, balance: Number(rec.balance||0), updated: rec.updated });
});

// POST /api/wallet/adjust  { username, delta, reason }
router.post("/adjust", async (req, res) => {
  const user = up(req.body?.username || "");
  const delta = Number(req.body?.delta || 0);
  if (!user || !Number.isFinite(delta) || !delta) return res.status(400).json({ ok:false, error:"bad_input" });

  const rec = await writeDelta(user, delta);
  if (!rec) return res.status(503).json({ ok:false, error:"store_offline" });

  res.setHeader("X-Store", mongoUp() ? "mongo" : (ALLOW_MEMORY_FALLBACK ? "memory" : "offline"));
  res.json({ ok:true, username: rec.username, balance: Number(rec.balance||0), updated: rec.updated });
});

// POST /api/wallet/credit { username, amount, reason }  (legacy fallback)
router.post("/credit", async (req, res) => {
  const user = up(req.body?.username || "");
  const amt = Number(req.body?.amount || 0);
  if (!user || !Number.isFinite(amt) || !amt) return res.status(400).json({ ok:false, error:"bad_input" });

  const rec = await writeDelta(user, amt);
  if (!rec) return res.status(503).json({ ok:false, error:"store_offline" });

  res.setHeader("X-Store", mongoUp() ? "mongo" : (ALLOW_MEMORY_FALLBACK ? "memory" : "offline"));
  res.json({ ok:true, username: rec.username, balance: Number(rec.balance||0), updated: rec.updated });
});

// GET /api/wallet/me?viewer=LASH3Z   (for player HUD convenience)
router.get("/me", async (req,res) => {
  const viewer = up(req.query.viewer || "");
  if (!viewer) return res.status(400).json({ ok:false, error:"bad_user" });
  const rec = await getOrCreate(viewer);
  if (!rec) return res.status(503).json({ ok:false, error:"store_offline" });
  res.setHeader("X-Store", mongoUp() ? "mongo" : (ALLOW_MEMORY_FALLBACK ? "memory" : "offline"));
  res.json({ ok:true, wallet: { username: rec.username, balance: Number(rec.balance||0), updated: rec.updated } });
});

export default router;
