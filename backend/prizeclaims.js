// backend/routes/prizeClaims.js (ESM)
import express from "express";
import mongoose from "mongoose";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const router = express.Router();
const mongoUp = () => mongoose?.connection?.readyState === 1;

// --- FS helpers (store screenshots on disk) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const DATA_DIR   = path.resolve(__dirname, "../../data");
const PC_DIR     = path.join(DATA_DIR, "prize_claims");

async function ensureDirs() {
  try { await fs.mkdir(PC_DIR, { recursive: true }); } catch {}
}
function up(s){ return String(s||"").trim().toUpperCase(); }
function sanitizeId(s){ return String(s||"").replace(/[^a-zA-Z0-9._-]/g,""); }

// --- Model ---
let PrizeClaim;
try {
  const PrizeClaimSchema = new mongoose.Schema({
    user:        { type: String, index: true },   // PLAYER username (UPPERCASE)
    affiliate:   { type: String, default: "" },   // affiliate username
    raffleRid:   { type: String, default: "" },   // which raffle they won
    asset:       { type: String, default: "USDT" },
    chain:       { type: String, default: "" },   // e.g. TRC20 / ERC20 / SOL / BTC / LTC
    walletAddr:  { type: String, default: "" },
    note:        { type: String, default: "" },
    screenshot:  { type: String, default: "" },   // relative file path (under /data/prize_claims)
    status:      { type: String, default: "pending", index: true }, // pending | approved | rejected
    adminNote:   { type: String, default: "" },
    createdAt:   { type: Date, default: () => new Date(), index: true },
    reviewedAt:  { type: Date, default: null }
  }, { versionKey: false, collection: "prize_claims" });

  PrizeClaim = mongoose.models.PrizeClaim || mongoose.model("PrizeClaim", PrizeClaimSchema);
} catch {}

// --- Admin guard (trust your server cookie) ---
function adminGuard(req, res, next) {
  const tok = req.cookies?.["adm_sess"];
  if (!tok) return res.status(401).json({ ok:false, error:"admin_locked" });
  next();
}

// --- POST /api/prize-claims  (player submits) ---
router.post("/", async (req, res) => {
  if (!mongoUp() || !PrizeClaim) return res.status(503).json({ ok:false, error:"DB_OFFLINE" });

  const user      = up(req.body?.user || req.body?.username);
  const affiliate = String(req.body?.affiliate || "");
  const raffleRid = up(req.body?.raffleRid || req.body?.rid || "");
  const wallet    = String(req.body?.walletAddr || req.body?.wallet || "");
  const asset     = String(req.body?.asset || "USDT");
  const chain     = String(req.body?.chain || "");
  const note      = String(req.body?.note || "");

  // screenshot as base64 (data URL or raw base64)
  const b64       = String(req.body?.screenshotBase64 || "");
  if (!user || !wallet) return res.status(400).json({ ok:false, error:"bad_input" });

  // persist claim
  const doc = await PrizeClaim.create({
    user, affiliate, raffleRid, walletAddr: wallet, asset, chain, note,
    status:"pending"
  });

  // optional screenshot write
  await ensureDirs();
  if (b64) {
    try {
      const raw = b64.includes(",") ? b64.split(",")[1] : b64;
      const buf = Buffer.from(raw, "base64");
      const ext = ".png";
      const fname = sanitizeId(doc._id.toString()) + ext;
      const rel   = `prize_claims/${fname}`;
      await fs.writeFile(path.join(DATA_DIR, rel), buf);
      doc.screenshot = rel;
      await doc.save();
    } catch(e) {
      // ignore screenshot failure, keep claim
    }
  }

  res.json({ ok:true, id: doc._id.toString() });
});

// --- ADMIN: list pending (or all) ---
router.get("/", adminGuard, async (req, res) => {
  if (!mongoUp() || !PrizeClaim) return res.status(503).json({ ok:false, error:"DB_OFFLINE" });
  const status = String(req.query.status || "pending");
  const q = status === "all" ? {} : { status };
  const rows = await PrizeClaim.find(q).sort({ createdAt: -1 }).lean();
  res.json({ ok:true, claims: rows });
});

// --- ADMIN: get single claim ---
router.get("/:id", adminGuard, async (req, res) => {
  if (!mongoUp() || !PrizeClaim) return res.status(503).json({ ok:false, error:"DB_OFFLINE" });
  const id = String(req.params.id||"");
  const row = await PrizeClaim.findById(id).lean();
  if (!row) return res.status(404).json({ ok:false, error:"not_found" });
  res.json({ ok:true, claim: row });
});

// --- ADMIN: serve screenshot (if any) ---
router.get("/:id/image", adminGuard, async (req, res) => {
  const id = String(req.params.id||"");
  if (!mongoUp() || !PrizeClaim) return res.status(503).json({ ok:false, error:"DB_OFFLINE" });
  const row = await PrizeClaim.findById(id).lean();
  if (!row || !row.screenshot) return res.status(404).end();
  try {
    await ensureDirs();
    const file = path.join(DATA_DIR, row.screenshot);
    res.setHeader("Cache-Control","no-cache");
    res.sendFile(file);
  } catch {
    res.status(404).end();
  }
});

// --- ADMIN: set status (approve/reject) ---
router.post("/:id/status", adminGuard, async (req, res) => {
  if (!mongoUp() || !PrizeClaim) return res.status(503).json({ ok:false, error:"DB_OFFLINE" });
  const id = String(req.params.id||"");
  const status = String(req.body?.status||"").toLowerCase();
  const adminNote = String(req.body?.adminNote||"");
  if (!["approved","rejected","pending"].includes(status)) return res.status(400).json({ ok:false, error:"bad_status" });

  const row = await PrizeClaim.findById(id);
  if (!row) return res.status(404).json({ ok:false, error:"not_found" });
  row.status = status;
  row.adminNote = adminNote;
  row.reviewedAt = new Date();
  await row.save();
  res.json({ ok:true });
});

export default router;
