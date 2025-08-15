// server.js — homepage-first, admin aliases, JSON+form login, + PVP API (DB or memory)
import fs from "fs";
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

const PUBLIC_DIR = process.env.PUBLIC_DIR
  ? path.resolve(process.env.PUBLIC_DIR)
  : __dirname;

const HOME_INDEX = (() => {
  const val = process.env.HOME_INDEX || "index.html";
  return path.isAbsolute(val) ? val : path.join(PUBLIC_DIR, val);
})();

function existsSync(p) { try { fs.accessSync(p); return true; } catch { return false; } }
const HAS_HOME = existsSync(HOME_INDEX);

// Resolve first matching admin login/hub file
function resolveFirstExisting(candidates) {
  for (const rel of candidates) {
    const abs = path.isAbsolute(rel) ? rel : path.join(PUBLIC_DIR, rel);
    if (existsSync(abs)) return abs;
  }
  return null;
}
const ADMIN_LOGIN_FILE = resolveFirstExisting([
  process.env.ADMIN_LOGIN_FILE || "pages/dashboard/home/admin_login.html",
  "pages/dashboard/home/login.html",
  "admin_login.html",
  "admin/index.html",
]);
const ADMIN_HUB_FILE = resolveFirstExisting([
  process.env.ADMIN_HUB_FILE || "pages/dashboard/admin/admin_hub.html",
  "admin/admin_hub.html",
]);

// ===== In-memory stores
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
  deposits: [],
  pvpEntries: []   // <— server copy when DB not available
};

// ===== App
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

// Light headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer-when-downgrade");
  res.setHeader("Permissions-Policy", "interest-cohort=()");
  next();
});

// Parsers
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
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: "12h" });
}
function verifyAdminToken(req, res, next) {
  const token = req.cookies?.admin_token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try { const decoded = jwt.verify(token, JWT_SECRET); req.adminUser = decoded.username; next(); }
  catch { return res.status(401).json({ error: "Unauthorized" }); }
}

// ===== Admin auth (JSON or form)
app.post(["/api/admin/gate/login", "/api/admin/login"], (req, res) => {
  const b = req.body || {};
  const username = (b.username || b.user || b.email || "").toString().trim();
  const password = (b.password || b.pass || b.pwd || "").toString();
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  if (username.toLowerCase() === ADMIN_USER && password === ADMIN_PASS) {
    res.cookie("admin_token", generateAdminToken(username.toLowerCase()), {
      httpOnly: true, sameSite: "lax", secure: NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 12, path: "/",
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

// ===== Health
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    env: NODE_ENV,
    port: PORT,
    publicDir: PUBLIC_DIR,
    homeIndex: HOME_INDEX,
    hasHome: HAS_HOME,
    adminLoginFile: ADMIN_LOGIN_FILE,
    hasAdminLogin: !!ADMIN_LOGIN_FILE,
    adminHubFile: ADMIN_HUB_FILE,
    hasAdminHub: !!ADMIN_HUB_FILE,
    db: !!globalThis.__dbReady
  });
});

// ===== Home
app.get("/", (req, res) => {
  if (HAS_HOME) return res.sendFile(HOME_INDEX);
  res.status(200).send("Homepage not found: put index.html in PUBLIC_DIR or set HOME_INDEX/PUBLIC_DIR correctly.");
});

// ===== Admin helper pages
app.get("/admin/login", (req, res) => {
  if (ADMIN_LOGIN_FILE) return res.sendFile(ADMIN_LOGIN_FILE);
  res.status(404).send("Admin login page not found.");
});
app.get("/admin/hub", (req, res) => {
  if (ADMIN_HUB_FILE) return res.sendFile(ADMIN_HUB_FILE);
  res.status(404).send("Admin hub page not found.");
});

// ===== Admin aliases (/admin/<file>.html → /pages/dashboard/admin/<file>.html)
const ADMIN_WHITELIST = new Set([
  "bets_admin.html",
  "battleground_admin.html",
  "battleground_widget.html",
  "bonus_hunt_admin.html",
  "bonus_hunt_widget.html",
  "pvp_admin.html",
  "lucky7.html",
  "admin_hub.html"
]);
app.get("/admin/:file", (req, res) => {
  const safe = String(req.params.file || "").replace(/[^a-zA-Z0-9_.-]/g, "");
  if (!ADMIN_WHITELIST.has(safe)) return res.status(404).send("Not found.");
  const abs = path.join(PUBLIC_DIR, "pages/dashboard/admin", safe);
  if (!existsSync(abs)) return res.status(404).send("Not found.");
  return res.sendFile(abs);
});

// Quick logout → home
app.get("/logout", (req, res) => {
  res.clearCookie("admin_token", { path: "/" });
  res.redirect(302, "/");
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

// ===== Minimal APIs already present (jackpot/rules/wallet/raffles/deposits) …
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

// ===== NEW: PVP API =====

// Public submit/update (upsert by username)
app.post("/api/pvp/entries", async (req, res) => {
  const username = String(req.body?.username || "").trim().toUpperCase();
  const side     = String(req.body?.side || "").trim().toUpperCase();   // "EAST"/"WEST"
  const game     = String(req.body?.game || "").trim();
  if (!username) return res.status(400).json({ error: "username required" });

  const doc = {
    username, side: side === "WEST" ? "WEST" : "EAST",
    game,
    status: "pending",
    ts: new Date()
  };

  try {
    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("pvp_entries");
      await col.updateOne({ username }, { $set: doc }, { upsert: true });
      const saved = await col.findOne({ username });
      return res.json({ success: true, entry: saved });
    } else {
      const idx = memory.pvpEntries.findIndex(e => e.username === username);
      if (idx >= 0) memory.pvpEntries[idx] = { ...memory.pvpEntries[idx], ...doc };
      else memory.pvpEntries.push({ _id: String(Date.now()), ...doc });
      const saved = memory.pvpEntries.find(e => e.username === username);
      return res.json({ success: true, entry: saved });
    }
  } catch (e) {
    console.error("[PVP] save failed", e);
    return res.status(500).json({ error: "save failed" });
  }
});

// Admin: list all entries
app.get("/api/pvp/entries", verifyAdminToken, async (req, res) => {
  try {
    if (globalThis.__dbReady) {
      const list = await globalThis.__db.collection("pvp_entries")
        .find().sort({ ts: -1 }).toArray();
      return res.json({ entries: list });
    } else {
      const list = [...memory.pvpEntries].sort((a,b)=> new Date(b.ts) - new Date(a.ts));
      return res.json({ entries: list });
    }
  } catch (e) {
    console.error("[PVP] list failed", e);
    return res.status(500).json({ error: "list failed" });
  }
});

// Admin: change status
app.post("/api/pvp/entries/:id/status", verifyAdminToken, async (req, res) => {
  const status = String(req.body?.status || "").toLowerCase(); // "approved" | "rejected" | "pending"
  if (!["approved","rejected","pending"].includes(status)) return res.status(400).json({ error: "bad status" });

  try {
    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("pvp_entries");
      const id = req.params.id;
      const q = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { username: id.toUpperCase() };
      const r = await col.updateOne(q, { $set: { status } });
      return res.json({ success: r.matchedCount > 0 });
    } else {
      const id = req.params.id;
      const i = memory.pvpEntries.findIndex(e => e._id === id || e.username === id.toUpperCase());
      if (i < 0) return res.json({ success: false });
      memory.pvpEntries[i].status = status;
      return res.json({ success: true });
    }
  } catch (e) {
    console.error("[PVP] status failed", e);
    return res.status(500).json({ error: "status failed" });
  }
});

// Admin: delete entry
app.delete("/api/pvp/entries/:id", verifyAdminToken, async (req, res) => {
  try {
    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("pvp_entries");
      const id = req.params.id;
      const q = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { username: id.toUpperCase() };
      const r = await col.deleteOne(q);
      return res.json({ success: r.deletedCount > 0 });
    } else {
      const id = req.params.id;
      const before = memory.pvpEntries.length;
      memory.pvpEntries = memory.pvpEntries.filter(e => e._id !== id && e.username !== id.toUpperCase());
      return res.json({ success: memory.pvpEntries.length !== before });
    }
  } catch (e) {
    console.error("[PVP] delete failed", e);
    return res.status(500).json({ error: "delete failed" });
  }
});

// ===== Default 404
app.use((req, res) => res.status(404).send("Not found."));

// ===== Error handler
app.use((err, req, res, next) => {
  console.error("[ERROR]", err?.stack || err);
  if (req.path.startsWith("/api")) return res.status(500).json({ error: "Server error" });
  res.status(500).send("Server error");
});

// ===== Start (non-blocking DB connect)
app.listen(PORT, HOST, () => {
  console.log(`[Server] http://${HOST}:${PORT} (${NODE_ENV}) PUBLIC_DIR=${PUBLIC_DIR}`);
  console.log(`[Server] HOME_INDEX=${HOME_INDEX} hasHome=${HAS_HOME}`);
  console.log(`[Server] ADMIN_LOGIN_FILE=${ADMIN_LOGIN_FILE || "(none)"} | ADMIN_HUB_FILE=${ADMIN_HUB_FILE || "(none)"}`);
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
