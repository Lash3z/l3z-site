// backend/routes/raffles.js (ESM)
import express from "express";
import mongoose from "mongoose";

const router = express.Router();

// ---- storage (mongo or memory) ----
const mem = { raffle: new Map() }; // id -> [{user, ts}]
const mongoUp = () => mongoose?.connection?.readyState === 1;

let RaffleEntry;
try {
  const schema = new mongoose.Schema({
    rid:  { type: String, index: true },
    user: { type: String, index: true },
    ts:   { type: Date,   default: () => new Date() },
  }, { versionKey: false });
  schema.index({ rid: 1, user: 1 }, { unique: true });
  RaffleEntry = mongoose.models.RaffleEntry || mongoose.model("RaffleEntry", schema);
} catch {}

/** GET /api/raffles/:id/entries */
router.get("/:id/entries", async (req, res) => {
  const rid = String(req.params.id || "").trim();
  if (!rid) return res.status(400).json({ ok: false, error: "bad_id" });

  if (mongoUp() && RaffleEntry) {
    const rows = await RaffleEntry.find({ rid }).sort({ ts: 1 }).lean();
    return res.json({ ok: true, entries: rows.map(r => ({ user: r.user, ts: r.ts })) });
  }
  const arr = Array.from(mem.raffle.get(rid) || []);
  return res.json({ ok: true, entries: arr });
});

/** POST /api/raffles/:id/entries { user } */
router.post("/:id/entries", async (req, res) => {
  const rid = String(req.params.id || "").trim();
  const user = String((req.body?.user || "").toUpperCase());
  if (!rid || !user) return res.status(400).json({ ok: false, error: "bad_input" });

  if (mongoUp() && RaffleEntry) {
    try {
      await RaffleEntry.updateOne(
        { rid, user },
        { $setOnInsert: { rid, user }, $set: { ts: new Date() } },
        { upsert: true }
      );
      return res.json({ ok: true });
    } catch (e) {
      if (e?.code === 11000) return res.json({ ok: true, already: true });
      return res.status(500).json({ ok: false, error: e?.message || "db_error" });
    }
  }

  const arr = mem.raffle.get(rid) || [];
  if (!arr.some(e => e.user === user)) arr.push({ user, ts: new Date().toISOString() });
  mem.raffle.set(rid, arr);
  return res.json({ ok: true });
});

export default router;
