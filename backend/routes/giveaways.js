// backend/routes/giveaways.js (ESM)
import express from "express";
import mongoose from "mongoose";

const router = express.Router();

/** --- Storage layer (Mongo if up, else in-memory) --- */
const mem = { slotwheel: new Map() }; // id -> [{user, ts}]
const mongoUp = () => mongoose?.connection?.readyState === 1;

let SlotwheelEntry;
try {
  const schema = new mongoose.Schema({
    gid:   { type: String, index: true },
    user:  { type: String, index: true },
    ts:    { type: Date,   default: () => new Date() },
  }, { versionKey: false });
  schema.index({ gid: 1, user: 1 }, { unique: true });
  SlotwheelEntry = mongoose.models.SlotwheelEntry || mongoose.model("SlotwheelEntry", schema);
} catch {
  // mongoose not available; ignore
}

/** GET /api/giveaways/slotwheel/:id/entries */
router.get("/slotwheel/:id/entries", async (req, res) => {
  const gid = String(req.params.id || "").trim();
  if (!gid) return res.status(400).json({ ok: false, error: "bad_id" });

  if (mongoUp() && SlotwheelEntry) {
    const rows = await SlotwheelEntry.find({ gid }).sort({ ts: 1 }).lean();
    return res.json({ ok: true, entries: rows.map(r => ({ user: r.user, ts: r.ts })) });
  }
  const arr = Array.from(mem.slotwheel.get(gid) || []);
  return res.json({ ok: true, entries: arr });
});

/** POST /api/giveaways/slotwheel/:id/entries { user } */
router.post("/slotwheel/:id/entries", async (req, res) => {
  const gid = String(req.params.id || "").trim();
  const user = String((req.body?.user || "").toUpperCase());
  if (!gid || !user) return res.status(400).json({ ok: false, error: "bad_input" });

  if (mongoUp() && SlotwheelEntry) {
    try {
      await SlotwheelEntry.updateOne(
        { gid, user },
        { $setOnInsert: { gid, user }, $set: { ts: new Date() } },
        { upsert: true }
      );
      return res.json({ ok: true });
    } catch (e) {
      // duplicate is also ok (already entered)
      if (e?.code === 11000) return res.json({ ok: true, already: true });
      return res.status(500).json({ ok: false, error: e?.message || "db_error" });
    }
  }

  // memory fallback
  const arr = mem.slotwheel.get(gid) || [];
  if (!arr.some(e => e.user === user)) arr.push({ user, ts: new Date().toISOString() });
  mem.slotwheel.set(gid, arr);
  return res.json({ ok: true });
});

export default router;
