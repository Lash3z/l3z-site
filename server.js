// server.js — L3Z site (Render-safe) with working admin gate + in-memory fallbacks
import fs from "fs/promises";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

// ===== ENV
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";

const ADMIN_USER   = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS   = process.env.ADMIN_PASS || "Lash3z777";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "supersecretkey";
const JWT_SECRET   = process.env.SECRET || ADMIN_SECRET;

const MONGO_URI = process.env.MONGO_URI || "";
const MONGO_DB  = process.env.MONGO_DB  || "lash3z";

// If Mongo is down, we keep running unless this is false
const ALLOW_MEMORY_FALLBACK = (process.env.ALLOW_MEMORY_FALLBACK || "true") === "true";

// Jackpot defaults
const JACKPOT_BASE_AUD     = Number(process.env.JACKPOT_BASE_AUD || 150);
const JACKPOT_PER_SUB_AUD  = Number(process.env.JACKPOT_PER_SUB_AUD || 2.5);
const JACKPOT_SUBS_CAP_AUD = Number(process.env.JACKPOT_SUBS_CAP_AUD || 100);

// ===== Paths
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// IMPORTANT: your project has /index.html at the repo root next to server.js.
// So we default PUBLIC_DIR to __dirname (not ./public). Can be overridden by env.
const PUBLIC_DIR = process.env.PUBLIC_DIR
  ? path.resolve(process.env.PUBLIC_DIR)
  : __dirname;

const UP_DIR = path.join(__dirname, "uploads");
await fs.mkdir(UP_DIR, { recursive: true });

// SPA presence check
let HAS_INDEX_HTML = false;
try {
  await fs.access(path.join(PUBLIC_DIR, "index.html"));
  HAS_INDEX_HTML = true;
} catch (e) {
  console.warn(`[Server] No index.html at ${path.join(PUBLIC_DIR, "index.html")} — root will show a simple message.`);
}

// ===== DB (optional; short timeout so boot never hangs)
let db = null;
if (MONGO_URI) {
  try {
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 8000 });
    await client.connect();
    db = client.db(MONGO_DB);
    console.log(`[DB] Connected to MongoDB: ${MONGO_DB}`);
  } catch (err) {
    console.error("[DB] Mongo connection failed:", err?.message || err);
    if (!ALLOW_MEMORY_FALLBACK) process.exit(1);
    console.warn("[DB] Using in-memory fallback.");
  }
} else if (!ALLOW_MEMORY_FALLBACK) {
  console.error("[DB] No MONGO_URI and memory fallback disabled. Exiting.");
  process.exit(1);
}

// ===== In-memory stores (safe defaults so the UI loads)
const memory = {
  jackpot: { amount: 0, month: new Date().toISOString().slice(0,7), perSubAUD: JACKPOT_PER_SUB_AUD },
  rules: {
    lbx: { SUB_NEW: 10, SUB_RENEW: 5, SUB_GIFT_GIFTER_PER: 2, SUB_GIFT_RECIPIENT: 3 },
    caps: { eventLBXPerUserPerDay: 100 },
    jackpotPerSubAUD: 2.50, jackpotCurrency: "AUD", depositContributesJackpot: false
  },
  events: [], // {ts,type,user,quantity,recipients,applied}
  wallets: {}, // { USERNAME: { balance: number } }
  raffles: [], // { rid, title, open, createdAt, winner, entries: [{user,ts}] }
  claims: [],  // { _id, user, raffleRid, affiliate, asset, chain, walletAddr, createdAt, status, screenshotPath }
  deposits: [] // pending deposits/orders
};

// ===== App
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

// ----- CORS only for /api
app.use("/api", (req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ===== Auth helpers
function generateAdminToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: "2h" });
}
function verifyAdminToken(req, res, next) {
  const token = req.cookies?.admin_token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.adminUser = decoded.username;
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

// ===== Admin auth routes (returns admin:true so your gate unlocks)
app.post(["/api/admin/gate/login", "/api/admin/login"], (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
  if (username.toLowerCase() === ADMIN_USER && password === ADMIN_PASS) {
    const token = generateAdminToken(username.toLowerCase());
    res.cookie("admin_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 2,
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

// ===== Health + landing
app.get("/api/health", (req, res) => {
  res.json({ ok: true, env: NODE_ENV, db: !!db, time: new Date().toISOString(), publicDir: PUBLIC_DIR, hasIndex: HAS_INDEX_HTML });
});

// Root: if index.html exists, serve it; otherwise show message
app.get("/", (req, res, next) => {
  if (HAS_INDEX_HTML) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"), (err) => err && next(err));
  }
  res.status(200).send("L3Z server is up. No SPA installed here. Set PUBLIC_DIR or add index.html next to server.js.");
});

// ===== Jackpot (very small impl)
app.get("/api/jackpot", async (req, res) => {
  res.json({ amount: Number(memory.jackpot.amount || 0), month: memory.jackpot.month, perSubAUD: memory.jackpot.perSubAUD });
});
app.post("/api/jackpot/adjust", verifyAdminToken, async (req, res) => {
  const { delta = 0, reason = "ADJUST" } = req.body || {};
  const d = Number(delta) || 0;
  memory.jackpot.amount = Number(memory.jackpot.amount || 0) + d;
  memory.events.unshift({ ts: Date.now(), type: "JACKPOT_ADJUST", user: req.adminUser, quantity: d, recipients: [], applied: true, reason });
  res.json({ success: true, amount: memory.jackpot.amount });
});

// ===== Events / Rules (minimal)
app.get("/api/events/rules", verifyAdminToken, (req, res) => {
  res.json({ rules: memory.rules });
});
app.put("/api/events/rules", verifyAdminToken, (req, res) => {
  const body = req.body || {};
  memory.rules = { ...memory.rules, ...body };
  res.json({ success: true, rules: memory.rules });
});
app.get("/api/events/recent", verifyAdminToken, (req, res) => {
  const limit = Math.max(1, Math.min(500, Number(req.query.limit || 200)));
  res.json({ events: memory.events.slice(0, limit) });
});

// ===== Simple Wallet endpoints used by UI
app.post("/api/wallet/adjust", verifyAdminToken, (req, res) => {
  const { username, delta = 0 } = req.body || {};
  const u = String(username||"").toUpperCase();
  if (!u) return res.status(400).json({ error: "username required" });
  const w = memory.wallets[u] || { balance: 0 };
  w.balance = Number(w.balance || 0) + Number(delta || 0);
  memory.wallets[u] = w;
  res.json({ success: true, wallet: w });
});
app.post("/api/wallet/credit", verifyAdminToken, (req, res) => {
  const { username, amount = 0 } = req.body || {};
  const u = String(username||"").toUpperCase();
  if (!u) return res.status(400).json({ error: "username required" });
  const w = memory.wallets[u] || { balance: 0 };
  w.balance = Number(w.balance || 0) + Number(amount || 0);
  memory.wallets[u] = w;
  res.json({ success: true, wallet: w });
});
app.get("/api/wallet/balance", verifyAdminToken, (req, res) => {
  const u = String(req.query.user||"").toUpperCase();
  const w = memory.wallets[u] || { balance: 0 };
  res.json({ balance: Number(w.balance||0) });
});
app.get("/api/wallet/me", verifyAdminToken, (req, res) => {
  const u = String(req.query.viewer||req.adminUser||"").toUpperCase();
  const w = memory.wallets[u] || { balance: 0 };
  res.json({ wallet: { balance: Number(w.balance||0) }});
});

// ===== Deposits (mock)
app.get("/api/deposits/pending", verifyAdminToken, (req, res) => {
  res.json({ orders: memory.deposits });
});
app.post("/api/deposits/:id/approve", verifyAdminToken, (req, res) => {
  const id = req.params.id;
  memory.deposits = memory.deposits.filter(o => String(o.id||o._id) !== String(id));
  res.json({ success: true });
});
app.post("/api/deposits/:id/reject", verifyAdminToken, (req, res) => {
  const id = req.params.id;
  memory.deposits = memory.deposits.filter(o => String(o.id||o._id) !== String(id));
  res.json({ success: true });
});

// ===== Raffles (minimal API used by admin page)
app.get("/api/raffles", verifyAdminToken, (req, res) => {
  const list = memory.raffles.map(r => ({ rid: r.rid, title: r.title, open: r.open, winner: r.winner || null, createdAt: r.createdAt }));
  res.json({ raffles: list });
});
app.post("/api/raffles", verifyAdminToken, (req, res) => {
  const { rid, title } = req.body || {};
  if (!rid || !title) return res.status(400).json({ error: "rid and title required" });
  if (memory.raffles.find(r => r.rid === rid)) return res.status(409).json({ error: "RID exists" });
  memory.raffles.unshift({ rid, title, open: true, createdAt: Date.now(), entries: [], winner: null });
  res.json({ success: true });
});
app.delete("/api/raffles", verifyAdminToken, (req, res) => {
  memory.raffles = [];
  res.json({ success: true });
});
app.put("/api/raffles/:rid/open", verifyAdminToken, (req, res) => {
  const { open } = req.body || {};
  const r = memory.raffles.find(x => x.rid === req.params.rid);
  if (!r) return res.status(404).json({ error: "not found" });
  r.open = !!open;
  res.json({ success: true });
});
app.get("/api/raffles/:rid/entries", verifyAdminToken, (req, res) => {
  const r = memory.raffles.find(x => x.rid === req.params.rid);
  if (!r) return res.status(404).json({ error: "not found" });
  res.json({ rid: r.rid, title: r.title, open: r.open, winner: r.winner || null, entries: r.entries || [] });
});
app.delete("/api/raffles/:rid/entries", verifyAdminToken, (req, res) => {
  const r = memory.raffles.find(x => x.rid === req.params.rid);
  if (!r) return res.status(404).json({ error: "not found" });
  r.entries = [];
  r.open = true;
  r.winner = null;
  res.json({ success: true });
});
app.post("/api/raffles/:rid/draw", verifyAdminToken, (req, res) => {
  const r = memory.raffles.find(x => x.rid === req.params.rid);
  if (!r) return res.status(404).json({ error: "not found" });
  const pool = r.entries || [];
  r.winner = pool.length ? pool[Math.floor(Math.random() * pool.length)].user : null;
  res.json({ success: true, winner: r.winner });
});

// ===== Prize claims (minimal)
app.get("/api/prize-claims", verifyAdminToken, (req, res) => {
  const status = String(req.query.status || "pending");
  const list = status === "all" ? memory.claims : memory.claims.filter(c => c.status === status);
  res.json({ claims: list });
});
app.get("/api/prize-claims/:id", verifyAdminToken, (req, res) => {
  const c = memory.claims.find(x => String(x._id) === String(req.params.id));
  if (!c) return res.status(404).json({ error: "not found" });
  res.json({ claim: c });
});
app.get("/api/prize-claims/:id/image", verifyAdminToken, async (req, res) => {
  const c = memory.claims.find(x => String(x._id) === String(req.params.id));
  if (!c || !c.screenshotPath) return res.status(404).send("no screenshot");
  res.sendFile(c.screenshotPath);
});
app.post("/api/prize-claims/:id/status", verifyAdminToken, (req, res) => {
  const c = memory.claims.find(x => String(x._id) === String(req.params.id));
  if (!c) return res.status(404).json({ error: "not found" });
  c.status = String(req.body?.status || "pending");
  res.json({ success: true });
});

// ===== Static
app.use(express.static(PUBLIC_DIR, {
  setHeaders(res, filePath) {
    if (/\.(png|jpe?g|gif|webp|svg|woff2?|mp3|mp4)$/i.test(filePath)) {
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    } else {
      res.setHeader("Cache-Control", "no-store");
    }
  }
}));

// ===== SPA fallback (if index exists)
app.get("*", (req, res, next) => {
  if (HAS_INDEX_HTML) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"), (err) => err && next(err));
  }
  res.status(404).send("Not found.");
});

// ===== Error handler
app.use((err, req, res, next) => {
  console.error("[ERROR]", err?.stack || err);
  if (req.path.startsWith("/api")) return res.status(500).json({ error: "Server error" });
  res.status(500).send("Server error");
});

// ===== Start
app.listen(PORT, HOST, () => {
  console.log(`[Server] http://${HOST}:${PORT} (${NODE_ENV}) PUBLIC_DIR=${PUBLIC_DIR} hasIndex=${HAS_INDEX_HTML}`);
});
