// server.js — Render-safe, accepts JSON *and* form posts, admin gate OK
import fs from "fs";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

// ===== ENV
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || "production";

const ADMIN_USER   = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS   = process.env.ADMIN_PASS || "Lash3z777";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "supersecretkey";
const JWT_SECRET   = process.env.SECRET || ADMIN_SECRET;

const MONGO_URI = process.env.MONGO_URI || "";
const MONGO_DB  = process.env.MONGO_DB  || "lash3z";

const ALLOW_MEMORY_FALLBACK = (process.env.ALLOW_MEMORY_FALLBACK || "true") === "true";

// ===== Paths
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// Serve static from the folder that holds your site; default to same dir as server.js.
// Override with PUBLIC_DIR if you serve from /public, /dist, etc.
const PUBLIC_DIR = process.env.PUBLIC_DIR
  ? path.resolve(process.env.PUBLIC_DIR)
  : __dirname;

const INDEX_PATH = path.join(PUBLIC_DIR, "index.html");
const HAS_INDEX_HTML = (() => { try { fs.accessSync(INDEX_PATH); return true; } catch { return false; } })();

// ===== In-memory stores (keeps UI functional without DB)
const memory = {
  jackpot: { amount: 0, month: new Date().toISOString().slice(0,7), perSubAUD: 2.5 },
  rules: {
    lbx: { SUB_NEW: 10, SUB_RENEW: 5, SUB_GIFT_GIFTER_PER: 2, SUB_GIFT_RECIPIENT: 3 },
    caps: { eventLBXPerUserPerDay: 100 },
    jackpotPerSubAUD: 2.50, jackpotCurrency: "AUD", depositContributesJackpot: false
  },
  events: [],
  wallets: {},
  raffles: [],
  claims: [],
  deposits: []
};

// ===== App
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

// Body parsers: JSON *and* forms
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// CORS only for /api
app.use("/api", (req, res, next) => {
  const origin = req.headers.origin;
  if (origin) { res.setHeader("Access-Control-Allow-Origin", origin); res.setHeader("Vary", "Origin"); }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ===== JWT helpers
function generateAdminToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: "12h" }); // 12h to match your UI note
}
function verifyAdminToken(req, res, next) {
  const token = req.cookies?.admin_token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try { const decoded = jwt.verify(token, JWT_SECRET); req.adminUser = decoded.username; next(); }
  catch { return res.status(401).json({ error: "Unauthorized" }); }
}

// ===== Admin auth (accepts JSON or form fields)
app.post(["/api/admin/gate/login", "/api/admin/login"], (req, res) => {
  const body = req.body || {};
  const username = (body.username || body.user || body.email || "").toString().trim();
  const password = (body.password || body.pass || body.pwd || "").toString();

  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  if (username.toLowerCase() === ADMIN_USER && password === ADMIN_PASS) {
    res.cookie("admin_token", generateAdminToken(username.toLowerCase()), {
      httpOnly: true,
      sameSite: "lax",
      secure: NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 12, // 12h
      path: "/",
    });
    return res.json({ success: true, admin: true, username: username.toLowerCase() });
  }
  return res.status(401).json({ error: "Invalid credentials" });
});

app.post(["/api/admin/gate/logout", "/api/admin/logout"], (req, res) => {
  res.clearCookie("admin_token", { path: "/" });
  res.json({ success: true });
});
app.get(["/api/admin/gate/check", "/api/admin/me"], verifyAdminToken, (req, res) => {
  res.json({ success: true, admin: true, username: req.adminUser });
});

// ===== Health + root
app.get("/api/health", (req, res) => {
  res.json({ ok: true, env: NODE_ENV, port: PORT, publicDir: PUBLIC_DIR, hasIndex: HAS_INDEX_HTML, db: !!globalThis.__dbReady });
});
app.get("/", (req, res, next) => {
  if (HAS_INDEX_HTML) return res.sendFile(INDEX_PATH, err => err && next(err));
  res.status(200).send("L3Z server is up. No SPA found. Set PUBLIC_DIR or place index.html next to server.js.");
});

// ===== Minimal APIs (unchanged behavior so your admin UI doesn’t error)
app.get("/api/jackpot", (req, res) => {
  res.json({ amount: Number(memory.jackpot.amount || 0), month: memory.jackpot.month, perSubAUD: memory.jackpot.perSubAUD });
});
app.post("/api/jackpot/adjust", verifyAdminToken, (req, res) => {
  const d = Number(req.body?.delta || 0);
  memory.jackpot.amount = Number(memory.jackpot.amount || 0) + d;
  memory.events.unshift({ ts: Date.now(), type: "JACKPOT_ADJUST", user: req.adminUser, quantity: d, recipients: [], applied: true });
  res.json({ success: true, amount: memory.jackpot.amount });
});

app.get("/api/events/rules", verifyAdminToken, (req, res) => res.json({ rules: memory.rules }));
app.put("/api/events/rules", verifyAdminToken, (req, res) => { memory.rules = { ...memory.rules, ...(req.body || {}) }; res.json({ success: true, rules: memory.rules }); });
app.get("/api/events/recent", verifyAdminToken, (req, res) => { const limit = Math.max(1, Math.min(500, Number(req.query.limit || 200))); res.json({ events: memory.events.slice(0, limit) }); });

app.post("/api/wallet/adjust", verifyAdminToken, (req, res) => {
  const u = String(req.body?.username || "").toUpperCase(); const delta = Number(req.body?.delta || 0);
  if (!u) return res.status(400).json({ error: "username required" });
  const w = memory.wallets[u] || { balance: 0 }; w.balance = Number(w.balance) + delta; memory.wallets[u] = w;
  res.json({ success: true, wallet: w });
});
app.post("/api/wallet/credit", verifyAdminToken, (req, res) => {
  const u = String(req.body?.username || "").toUpperCase(); const amount = Number(req.body?.amount || 0);
  if (!u) return res.status(400).json({ error: "username required" });
  const w = memory.wallets[u] || { balance: 0 }; w.balance = Number(w.balance) + amount; memory.wallets[u] = w;
  res.json({ success: true, wallet: w });
});
app.get("/api/wallet/balance", verifyAdminToken, (req, res) => { const u = String(req.query.user || "").toUpperCase(); const w = memory.wallets[u] || { balance: 0 }; res.json({ balance: Number(w.balance || 0) }); });
app.get("/api/wallet/me", verifyAdminToken, (req, res) => { const u = String(req.query.viewer || req.adminUser || "").toUpperCase(); const w = memory.wallets[u] || { balance: 0 }; res.json({ wallet: { balance: Number(w.balance || 0) } }); });

app.get("/api/deposits/pending", verifyAdminToken, (req, res) => res.json({ orders: memory.deposits }));
app.post("/api/deposits/:id/approve", verifyAdminToken, (req, res) => { const id = String(req.params.id); memory.deposits = memory.deposits.filter(o => String(o.id||o._id) !== id); res.json({ success: true }); });
app.post("/api/deposits/:id/reject", verifyAdminToken, (req, res) => { const id = String(req.params.id); memory.deposits = memory.deposits.filter(o => String(o.id||o._id) !== id); res.json({ success: true }); });

app.get("/api/raffles", verifyAdminToken, (req, res) => { res.json({ raffles: memory.raffles.map(r => ({ rid:r.rid, title:r.title, open:r.open, winner:r.winner||null, createdAt:r.createdAt })) }); });
app.post("/api/raffles", verifyAdminToken, (req, res) => {
  const rid = String(req.body?.rid || "").trim().toUpperCase();
  const title = String(req.body?.title || "").trim();
  if (!rid || !title) return res.status(400).json({ error: "rid and title required" });
  if (memory.raffles.find(r => r.rid === rid)) return res.status(409).json({ error: "RID exists" });
  memory.raffles.unshift({ rid, title, open:true, createdAt: Date.now(), entries: [], winner:null });
  res.json({ success: true });
});
app.delete("/api/raffles", verifyAdminToken, (req, res) => { memory.raffles = []; res.json({ success:true }); });
app.put("/api/raffles/:rid/open", verifyAdminToken, (req, res) => { const r = memory.raffles.find(x => x.rid === req.params.rid); if (!r) return res.status(404).json({ error:"not found" }); r.open = !!(req.body?.open); res.json({ success:true }); });
app.get("/api/raffles/:rid/entries", verifyAdminToken, (req, res) => { const r = memory.raffles.find(x => x.rid === req.params.rid); if (!r) return res.status(404).json({ error:"not found" }); res.json({ rid:r.rid, title:r.title, open:r.open, winner:r.winner||null, entries:r.entries||[] }); });
app.delete("/api/raffles/:rid/entries", verifyAdminToken, (req, res) => { const r = memory.raffles.find(x => x.rid === req.params.rid); if (!r) return res.status(404).json({ error:"not found" }); r.entries = []; r.open = true; r.winner = null; res.json({ success:true }); });
app.post("/api/raffles/:rid/draw", verifyAdminToken, (req, res) => { const r = memory.raffles.find(x => x.rid === req.params.rid); if (!r) return res.status(404).json({ error:"not found" }); const pool = r.entries || []; r.winner = pool.length ? pool[Math.floor(Math.random()*pool.length)].user : null; res.json({ success:true, winner:r.winner }); });

// Static files
app.use(express.static(PUBLIC_DIR, {
  setHeaders(res, filePath) {
    if (/\.(png|jpe?g|gif|webp|svg|woff2?|mp3|mp4)$/i.test(filePath)) res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    else res.setHeader("Cache-Control", "no-store");
  }
}));

// ---- Landing-only change below ----
// Instead of a SPA catch-all rewrite, we 404 unknown paths to prevent landing on admin.
// (Everything else above remains exactly as-is.)
app.use((req, res) => {
  res.status(404).send("Not found.");
});

// Error handler
app.use((err, req, res, next) => {
  console.error("[ERROR]", err?.stack || err);
  if (req.path.startsWith("/api")) return res.status(500).json({ error: "Server error" });
  res.status(500).send("Server error");
});

// Start (non-blocking DB connect)
app.listen(PORT, HOST, () => {
  console.log(`[Server] http://${HOST}:${PORT} (${NODE_ENV}) PUBLIC_DIR=${PUBLIC_DIR} hasIndex=${HAS_INDEX_HTML}`);
});
(async () => {
  if (!MONGO_URI) { if (!ALLOW_MEMORY_FALLBACK) console.warn("[DB] No MONGO_URI; memory mode."); return; }
  try {
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 8000 });
    await client.connect();
    globalThis.__db = client.db(MONGO_DB);
    globalThis.__dbReady = true;
    console.log(`[DB] Connected to MongoDB: ${MONGO_DB}`);
  } catch (err) {
    console.error("[DB] Mongo connection failed:", err?.message || err);
    if (!ALLOW_MEMORY_FALLBACK) { console.error("[DB] ALLOW_MEMORY_FALLBACK=false — exiting"); process.exit(1); }
    console.warn("[DB] Continuing in memory mode.");
  }
})();
