// backend/routes/giveaways.js (ESM)
import express from "express";
import mongoose from "mongoose";

const router = express.Router();

const mongoUp = () => mongoose?.connection?.readyState === 1;
const ALLOW_MEMORY_FALLBACK = String(process.env.ALLOW_MEMORY_FALLBACK || "").toLowerCase() === "true";

/** --- Storage layer (Mongo if up, else optional in-memory) --- */
const mem = { slotwheel: new Map() }; // id -> [{user, ts}]

let SlotwheelEntry;
try {
  const schema = new mongoose.Schema({
    gid:   { type: String, index: true },
    user:  { type: String, index: true },
    ts:    { type: Date,   default: () => new Date() },
  }, { versionKey: false, collection: "slotwheel_entries" });
  schema.index({ gid: 1, user: 1 }, { unique: true });
  SlotwheelEntry = mongoose.models.SlotwheelEntry || mongoose.model("SlotwheelEntry", schema);
} catch {
  // mongoose not ready; ignore
}

const up = (s) => (s || "").toString().trim().toUpperCase();

/** GET /api/giveaways/slotwheel/:id/entries */
router.get("/slotwheel/:id/entries", async (req, res) => {
  const gid = up(req.params.id || "");
  if (!gid) return res.status(400).json({ ok: false, error: "bad_id" });

  if (mongoUp() && SlotwheelEntry) {
    const rows = await SlotwheelEntry.find({ gid }).sort({ ts: 1 }).lean();
    res.setHeader("X-Store", "mongo");
    return res.json({ ok: true, entries: rows.map(r => ({ user: r.user, ts: r.ts })) });
  }

  if (!ALLOW_MEMORY_FALLBACK) {
    res.setHeader("X-Store", "offline");
    return res.status(503).json({ ok: false, reason: "DB_OFFLINE", entries: [] });
  }

  const arr = Array.from(mem.slotwheel.get(gid) || []);
  res.setHeader("X-Store", "memory");
  return res.json({ ok: true, entries: arr });
});

/** POST /api/giveaways/slotwheel/:id/entries { user } */
router.post("/slotwheel/:id/entries", async (req, res) => {
  const gid = up(req.params.id || "");
  const user = up(req.body?.user || "");
  if (!gid || !user) return res.status(400).json({ ok: false, error: "bad_input" });

  if (mongoUp() && SlotwheelEntry) {
    try {
      await SlotwheelEntry.updateOne(
        { gid, user },
        { $setOnInsert: { gid, user }, $set: { ts: new Date() } },
        { upsert: true }
      );
      res.setHeader("X-Store", "mongo");
      return res.json({ ok: true });
    } catch (e) {
      if (e?.code === 11000) { res.setHeader("X-Store", "mongo"); return res.json({ ok: true, already: true }); }
      return res.status(500).json({ ok: false, error: e?.message || "db_error" });
    }
  }

  if (!ALLOW_MEMORY_FALLBACK) {
    res.setHeader("X-Store", "offline");
    return res.status(503).json({ ok: false, reason: "DB_OFFLINE" });
  }

  // memory fallback
  const arr = mem.slotwheel.get(gid) || [];
  if (!arr.some(e => e.user === user)) arr.push({ user, ts: new Date().toISOString() });
  mem.slotwheel.set(gid, arr);
  res.setHeader("X-Store", "memory");
  return res.json({ ok: true });
});

export default router;
