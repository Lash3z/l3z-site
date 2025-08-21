// /backend/routes/jackpot.js
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

const DATA_DIR = path.join(__dirname, "..", "..", "data");
const FILE = path.join(DATA_DIR, "jackpot.json");

function ensureData(){
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(FILE)) fs.writeFileSync(FILE, JSON.stringify({ amount: 0, updatedAt: Date.now() }, null, 2));
}

function readJackpot(){
  try { ensureData(); return JSON.parse(fs.readFileSync(FILE, "utf8")); }
  catch (_) { return { amount: 0, updatedAt: Date.now() }; }
}
function writeJackpot(obj){
  ensureData(); fs.writeFileSync(FILE, JSON.stringify(obj, null, 2));
}

function isAdmin(req){
  // Accept either Basic auth OR an admin cookie set elsewhere in your admin login
  // Basic: Authorization: Basic base64(user:pass)
  try{
    const hdr = req.headers.authorization || "";
    if (hdr.startsWith("Basic ")) {
      const pair = Buffer.from(hdr.slice(6), "base64").toString("utf8");
      const idx = pair.indexOf(":");
      const user = pair.slice(0, idx), pass = pair.slice(idx+1);
      if (user === (process.env.ADMIN_USER||"LASH3Z") && pass === (process.env.ADMIN_PASS||"LASH3Z777")) return true;
    }
  }catch(_){}
  // Or cookie set by your admin auth flow: admin=1
  if (req.cookies && req.cookies.admin === "1") return true;
  return false;
}

// Viewers: get the current jackpot (grow-only number)
router.get("/", (req, res) => {
  const jp = readJackpot();
  res.json({ ok: true, amount: jp.amount, updatedAt: jp.updatedAt });
});

// Admin: contribute delta (positive or negative, but not below zero)
router.post("/contribute", (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ ok:false, error:"Unauthorized" });
  const delta = Number(req.body && req.body.delta);
  if (!isFinite(delta)) return res.status(400).json({ ok:false, error:"delta must be a number" });
  const jp = readJackpot();
  const next = Math.max(0, Number(jp.amount||0) + delta);
  const updated = { amount: next, updatedAt: Date.now() };
  writeJackpot(updated);
  res.json({ ok:true, amount: updated.amount, updatedAt: updated.updatedAt });
});

module.exports = router;
