// backend/routes/raffles.js
import express from "express";
import mongoose from "mongoose";

const router = express.Router();
const mongoUp = () => mongoose?.connection?.readyState === 1;

/* ------------------------------
   MODELS
------------------------------ */
let Raffle;
try {
  const EntrySchema = new mongoose.Schema(
    { user: { type: String, index: true }, ts: { type: Date, default: () => new Date() } },
    { _id: false }
  );
  const RaffleSchema = new mongoose.Schema(
    {
      rid:   { type: String, unique: true, index: true },     // slug/id (e.g. "AUG15-MATESLOTS")
      title: { type: String, required: true },                 // human title shown to players
      open:  { type: Boolean, default: true },                 // accepting entries
      entries: { type: [EntrySchema], default: [] },           // [{user, ts}]
      winner: { type: String, default: "" },                   // winning username
      drawnAt: { type: Date, default: null },
      createdAt: { type: Date, default: () => new Date() }
    },
    { versionKey: false, collection: "raffles" }
  );
  Raffle = mongoose.models.Raffle || mongoose.model("Raffle", RaffleSchema);
} catch {}

/* ------------------------------
   ADMIN GUARD (reuse server cookie)
------------------------------ */
function adminGuard(req, res, next) {
  // If server mounted this file under /api/raffles, you already have the cookie middleware.
  // We accept that /api/admin/gate/check is the true gate; keep behavior same as your server's adminGuard.
  const tok = req.cookies?.["adm_sess"];
  if (!tok) return res.status(401).json({ ok: false, error: "admin_locked" });
  next();
}

/* ------------------------------
   HELPERS
------------------------------ */
function up(s){ return String(s||"").trim().toUpperCase(); }
function ensureMongo(res){
  if (!mongoUp() || !Raffle) {
    res.status(503).json({ ok:false, error:"DB_OFFLINE" });
    return false;
  }
  return true;
}

/* ------------------------------
   PUBLIC – list raffles (open first), winners
------------------------------ */
router.get("/", async (_req, res) => {
  if (!ensureMongo(res)) return;
  const rows = await Raffle.find({})
    .sort({ open: -1, createdAt: -1 })
    .select({ _id:0, rid:1, title:1, open:1, winner:1, drawnAt:1, createdAt:1 })
    .lean();
  res.json({ ok:true, raffles: rows });
});

router.get("/:rid/entries", async (req, res) => {
  if (!ensureMongo(res)) return;
  const rid = String(req.params.rid||"").trim();
  if (!rid) return res.status(400).json({ ok:false, error:"bad_id" });
  const rf = await Raffle.findOne({ rid }).lean();
  if (!rf) return res.status(404).json({ ok:false, error:"not_found" });
  res.json({ ok:true, rid: rf.rid, title: rf.title, open: rf.open, winner: rf.winner||"", entries: rf.entries||[] });
});

router.get("/winners/recent", async (_req, res) => {
  if (!ensureMongo(res)) return;
  const rows = await Raffle.find({ winner: { $ne: "" } })
    .sort({ drawnAt: -1 })
    .limit(20)
    .select({ _id:0, rid:1, title:1, winner:1, drawnAt:1 })
    .lean();
  res.json({ ok:true, winners: rows });
});

/* ------------------------------
   PUBLIC – enter a raffle
------------------------------ */
router.post("/:rid/enter", async (req, res) => {
  if (!ensureMongo(res)) return;
  const rid   = String(req.params.rid||"").trim();
  const uname = up(req.body?.username || req.body?.user);
  if (!rid || !uname) return res.status(400).json({ ok:false, error:"bad_input" });

  const rf = await Raffle.findOne({ rid });
  if (!rf)   return res.status(404).json({ ok:false, error:"not_found" });
  if (!rf.open) return res.status(400).json({ ok:false, error:"closed" });

  // reject duplicate user
  if (rf.entries.some(e => up(e.user) === uname)) return res.json({ ok:true, already:true });

  rf.entries.push({ user: uname, ts:new Date() });
  await rf.save();

  res.json({ ok:true, rid: rf.rid, title: rf.title });
});

/* ------------------------------
   ADMIN – create, open/close, draw, clear, delete-all
------------------------------ */
router.post("/", adminGuard, async (req, res) => {
  if (!ensureMongo(res)) return;
  const rid   = String(req.body?.rid||"").trim();
  const title = String(req.body?.title||"").trim();
  if (!rid || !title) return res.status(400).json({ ok:false, error:"bad_input" });

  const exists = await Raffle.findOne({ rid }).lean();
  if (exists) return res.status(409).json({ ok:false, error:"exists" });

  await Raffle.create({ rid, title, open:true, entries:[] });
  res.json({ ok:true, rid, title, open:true });
});

router.put("/:rid/open", adminGuard, async (req, res) => {
  if (!ensureMongo(res)) return;
  const rid = String(req.params.rid||"").trim();
  const open = Boolean(req.body?.open);
  const rf = await Raffle.findOneAndUpdate({ rid }, { $set:{ open } }, { new:true });
  if (!rf) return res.status(404).json({ ok:false, error:"not_found" });
  res.json({ ok:true, rid: rf.rid, open: rf.open });
});

router.post("/:rid/draw", adminGuard, async (req, res) => {
  if (!ensureMongo(res)) return;
  const rid = String(req.params.rid||"").trim();
  const rf = await Raffle.findOne({ rid });
  if (!rf) return res.status(404).json({ ok:false, error:"not_found" });
  if (!rf.entries?.length) return res.status(400).json({ ok:false, error:"no_entries" });

  const idx = Math.floor(Math.random() * rf.entries.length);
  const winner = up(rf.entries[idx].user);

  rf.winner = winner;
  rf.drawnAt = new Date();
  rf.open = false;
  await rf.save();

  res.json({ ok:true, rid: rf.rid, title: rf.title, winner, drawnAt: rf.drawnAt });
});

router.delete("/:rid/entries", adminGuard, async (req, res) => {
  if (!ensureMongo(res)) return;
  const rid = String(req.params.rid||"").trim();
  const rf = await Raffle.findOne({ rid });
  if (!rf) return res.status(404).json({ ok:false, error:"not_found" });
  rf.entries = [];
  rf.winner = "";
  rf.drawnAt = null;
  rf.open = true;
  await rf.save();
  res.json({ ok:true, rid, cleared:true });
});

router.delete("/", adminGuard, async (_req, res) => {
  if (!ensureMongo(res)) return;
  await Raffle.deleteMany({});
  res.json({ ok:true, deletedAll:true });
});

export default router;
