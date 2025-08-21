// server.js — full ESM build (TOTAL ROUNDS BANDS from Battleground; Bets drafts/publish)
// + Wallet persistence (Mongo or memory) and one-time SIGNUP_BONUS
import fs from "fs";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { fileURLToPath } from "url";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

/* ===================== ENV ===================== */
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || "production";

const ADMIN_USER   = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS   = process.env.ADMIN_PASS   || "Lash3z777";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "dev_admin_secret";
const JWT_SECRET   = process.env.SECRET || ADMIN_SECRET;

// 🔒 Keep admin pages locked (turn ON security by default)
const DISABLE_ADMIN_AUTH =
  (process.env.DISABLE_ADMIN_AUTH ?? (process.env.NODE_ENV !== "production" ? "true" : "false")) === "true";

const MONGO_URI = process.env.MONGO_URI || "";
const MONGO_DB  = process.env.MONGO_DB  || "lash3z";
const ALLOW_MEMORY_FALLBACK = (process.env.ALLOW_MEMORY_FALLBACK || "true") === "true";

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(s=>s.trim()).filter(Boolean);

const SIGNUP_BONUS = Number(process.env.SIGNUP_BONUS || 0);

if (
  NODE_ENV === "production" &&
  !DISABLE_ADMIN_AUTH &&
  (!ADMIN_USER || !ADMIN_PASS || !ADMIN_SECRET || !JWT_SECRET)
) {
  console.error("[SECURITY] Missing required admin credentials/secrets in production.");
  process.exit(1);
}

/* ===================== Paths ===================== */
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const PUBLIC_DIR = process.env.PUBLIC_DIR
  ? path.resolve(process.env.PUBLIC_DIR)
  : __dirname;

const HOME_INDEX = (() => {
  const val = process.env.HOME_INDEX || "index.html";
  return path.isAbsolute(val) ? val : path.join(PUBLIC_DIR, val);
})();
function existsSync(p){ try { fs.accessSync(p); return true; } catch { return false; } }
const HAS_HOME = existsSync(HOME_INDEX);

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

/* ===================== Memory ===================== */
const memory = {
  jackpot: { amount: 0, month: new Date().toISOString().slice(0,7), perSubAUD: 2.5 },
  rules: {
    lbx: { SUB_NEW: 10, SUB_RENEW: 5, SUB_GIFT_GIFTER_PER: 2, SUB_GIFT_RECIPIENT: 3 },
    caps: { eventLBXPerUserPerDay: 100 },
    jackpotPerSubAUD: 2.50, jackpotCurrency: "AUD", depositContributesJackpot: false
  },
  events: [],
  wallets: {},        // legacy in-memory wallets (used if DB is unavailable)
  users: new Map(),   // in-memory users (only if DB is unavailable)
  raffles: [],
  claims: [],
  deposits: [],
  profiles: {},
  pvpEntries: [],
  pvpBracket: null,
  live: { pvp: null, battleground: null, bonus: null },

  // Bets
  betsDrafts: [],
  betsPublished: [],

  // Feature flags
  flags: { pvpEntriesOpen: true }
};

/* ===================== App ===================== */
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

// security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "interest-cohort=()");
  next();
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// CORS for /api
app.use("/api", (req, res, next) => {
  const origin = req.headers.origin;
  const allowAllInDev = NODE_ENV !== "production" && !ALLOWED_ORIGINS.length;
  if (origin && (allowAllInDev || ALLOWED_ORIGINS.includes(origin))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

/* ===================== Admin auth ===================== */
function generateAdminToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: "12h" });
}
function verifyAdminToken(req, res, next) {
  if (DISABLE_ADMIN_AUTH) {
    req.adminUser = (process.env.ADMIN_USER || "dev").toLowerCase();
    return next();
  }
  const token = req.cookies?.admin_token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.adminUser = decoded.username;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

// ==== Admin identity helpers (unified login) ====
const ADMIN_USERNAMES = (process.env.ADMIN_WHITELIST || ADMIN_USER)
  .split(",").map(s => s.trim().toUpperCase()).filter(Boolean);

const isAdminName = (u) => ADMIN_USERNAMES.includes(String(u||"").toUpperCase());

function setAdminCookie(res, username){
  res.cookie("admin_token", generateAdminToken(String(username||"").toLowerCase()), {
    httpOnly: true, sameSite: "strict", secure: NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 12, path: "/",
  });
}
function hasValidAdminCookie(req){
  const t = req.cookies?.admin_token;
  if (!t) return false;
  try { const d = jwt.verify(t, JWT_SECRET); return isAdminName(d.username); }
  catch { return false; }
}

const loginHits = new Map();
function rateLimitLogin(req, res, next){
  const ip = req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress || "unknown";
  const now = Date.now();
  const rec = loginHits.get(ip) || { count:0, ts:now };
  if (now - rec.ts > 10*60*1000) { rec.count = 0; rec.ts = now; }
  rec.count++; loginHits.set(ip, rec);
  if (rec.count > 30) return res.status(429).json({ error: "Too many attempts, try later" });
  next();
}
app.post(["/api/admin/gate/login", "/api/admin/login"], rateLimitLogin, (req, res) => {
  if (DISABLE_ADMIN_AUTH) {
    const username = (process.env.ADMIN_USER || "dev").toLowerCase();
    setAdminCookie(res, username);
    return res.json({ success: true, admin: true, username });
  }
  const b = req.body || {};
  const username = (b.username || b.user || b.email || "").toString().trim();
  const password = (b.password || b.pass || b.pwd || "").toString();
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
  if (username.toLowerCase() === ADMIN_USER && password === ADMIN_PASS) {
    setAdminCookie(res, username.toLowerCase());
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

/* ===================== Health/Home/Admin pages ===================== */
app.get("/api/health", (req, res) => {
  res.json({
    ok: true, env: NODE_ENV, port: PORT,
    publicDir: PUBLIC_DIR, homeIndex: HOME_INDEX, hasHome: HAS_HOME,
    adminLoginFile: ADMIN_LOGIN_FILE, hasAdminLogin: !!ADMIN_LOGIN_FILE,
    adminHubFile: ADMIN_HUB_FILE, hasAdminHub: !!ADMIN_HUB_FILE,
    db: !!globalThis.__dbReady,
    adminBypass: DISABLE_ADMIN_AUTH
  });
});
app.get("/api/ping", (req,res)=> res.json({ ok:true, ts: Date.now() }));

// --- Tracking / analytics no-op (silences console 404s) ---
app.all("/api/track/visit", (req, res) => res.status(204).end());

app.get("/", (req, res) => {
  if (HAS_HOME) return res.sendFile(HOME_INDEX);
  res.status(200).send("Homepage not found: put index.html in PUBLIC_DIR or set HOME_INDEX/PUBLIC_DIR correctly.");
});
app.get("/admin/login", (req, res) => {
  if (ADMIN_LOGIN_FILE) return res.sendFile(ADMIN_LOGIN_FILE);
  res.status(404).send("Admin login page not found.");
});
app.get("/admin/hub", (req, res) => {
  if (ADMIN_HUB_FILE) return res.sendFile(ADMIN_HUB_FILE);
  res.status(404).send("Admin hub page not found.");
});

// Admin aliases (file names)
const ADMIN_FILE_WHITELIST = new Set([
  "bets_admin.html","battleground_admin.html","battleground_widget.html",
  "bonus_hunt_admin.html","bonus_hunt_widget.html","pvp_admin.html",
  "lucky7.html","admin_hub.html"
]);
app.get("/admin/:file", (req, res) => {
  const safe = String(req.params.file || "").replace(/[^a-zA-Z0-9_.-]/g, "");
  if (!ADMIN_FILE_WHITELIST.has(safe)) return res.status(404).send("Not found.");
  const abs = path.join(PUBLIC_DIR, "pages/dashboard/admin", safe);
  if (!existsSync(abs)) return res.status(404).send("Not found.");
  return res.sendFile(abs);
});

app.get("/logout", (req, res) => {
  res.clearCookie("admin_token", { path: "/" });
  res.redirect(302, "/");
});

/* ===================== Static ===================== */
app.use(express.static(PUBLIC_DIR, {
  setHeaders(res, filePath) {
    if (/\.(png|jpe?g|gif|webp|svg|woff2?|mp3|mp4)$/i.test(filePath)) {
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    } else if (/\.(css|js|map)$/i.test(filePath)) {
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    } else if (/\.html$/i.test(filePath)) {
      res.setHeader("Cache-Control", "no-store");
    } else {
      res.setHeader("Cache-Control", "no-store");
    }
  }
}));

/* ======================================================================== */
/* ===================== WALLET / USER HELPERS (NEW) ====================== */
/* ======================================================================== */

const U = (s) => String(s || "").trim().toUpperCase();
const nowISO = () => new Date().toISOString();

// get or create wallet (does NOT apply bonus)
async function getWallet(username) {
  const user = U(username);
  if (!user) return { username: "", balance: 0 };

  if (globalThis.__dbReady) {
    const col = globalThis.__db.collection("wallets");
    const found = await col.findOne({ username: user });
    if (found) {
      return {
        username: user,
        balance: Number(found.balance || 0),
        signupBonusGrantedAt: found.signupBonusGrantedAt ?? null
      };
    }
    const fresh = { username: user, balance: 0, ledger: [], signupBonusGrantedAt: null };
    await col.insertOne(fresh);
    return { username: user, balance: 0, signupBonusGrantedAt: null };
  }

  // memory
  const w = memory.wallets[user] || { balance: 0, signupBonusGrantedAt: null, ledger: [] };
  memory.wallets[user] = w;
  return { username: user, balance: Number(w.balance || 0), signupBonusGrantedAt: w.signupBonusGrantedAt };
}

// credit/debit
async function adjustWallet(username, delta, reason = "adjust") {
  const user = U(username);
  const amount = Number(delta || 0);
  if (!user || !Number.isFinite(amount)) return { ok: false, error: "bad_params" };

  if (globalThis.__dbReady) {
    const col = globalThis.__db.collection("wallets");
    const tx  = { ts: nowISO(), delta: amount, reason };
    const r = await col.findOneAndUpdate(
      { username: user },
      {
        $setOnInsert: { username: user, balance: 0, ledger: [], signupBonusGrantedAt: null },
        $inc: { balance: amount },
        $push: { ledger: tx }
      },
      { upsert: true, returnDocument: "after" }
    );
    return { ok: true, balance: Number(r.value?.balance || 0) };
  }

  // memory
  const w = memory.wallets[user] || { balance: 0, ledger: [], signupBonusGrantedAt: null };
  w.balance = Number(w.balance || 0) + amount;
  w.ledger.push({ ts: nowISO(), delta: amount, reason });
  memory.wallets[user] = w;
  return { ok: true, balance: w.balance };
}

// grant one-time signup bonus
async function grantSignupBonusIfNeeded(username) {
  const user = U(username);
  const bonus = SIGNUP_BONUS;
  if (!user || !bonus) return { ok: true, skipped: true };

  if (globalThis.__dbReady) {
    const col = globalThis.__db.collection("wallets");
    const existing = await col.findOne({ username: user }, { projection: { signupBonusGrantedAt: 1, balance: 1 } });
    if (existing?.signupBonusGrantedAt) {
      return { ok: true, skipped: true, balance: Number(existing.balance || 0) };
    }
    const tx = { ts: nowISO(), delta: bonus, reason: "signup_bonus" };
    const r = await col.findOneAndUpdate(
      { username: user },
      {
        $setOnInsert: { username: user, balance: 0, ledger: [] },
        $inc: { balance: bonus },
        $set: { signupBonusGrantedAt: new Date() },
        $push: { ledger: tx }
      },
      { upsert: true, returnDocument: "after" }
    );
    return { ok: true, balance: Number(r.value?.balance || 0) };
  }

  // memory
  const w = memory.wallets[user] || { balance: 0, ledger: [], signupBonusGrantedAt: null };
  if (w.signupBonusGrantedAt) return { ok: true, skipped: true, balance: Number(w.balance || 0) };
  w.balance = Number(w.balance || 0) + bonus;
  w.signupBonusGrantedAt = new Date();
  w.ledger.push({ ts: nowISO(), delta: bonus, reason: "signup_bonus" });
  memory.wallets[user] = w;
  return { ok: true, balance: w.balance };
}

// optional: simple users store for /register when Mongo exists; memory fallback
async function userFind(username) {
  const u = U(username);
  if (!u) return null;
  if (globalThis.__dbReady) {
    return await globalThis.__db.collection("users").findOne({ username: u });
  }
  return memory.users.get(u) || null;
}
async function userCreate(username, passHash) {
  const u = U(username);
  const doc = { username: u, passHash, createdAt: new Date() };
  if (globalThis.__dbReady) {
    await globalThis.__db.collection("users").insertOne(doc);
  } else {
    memory.users.set(u, doc);
  }
  return doc;
}

/* ===================== Minimal APIs you had ===================== */
function walletAdjustHandler(req, res){
  const u = String(req.body?.username || req.body?.user || req.body?.name || "").toUpperCase();
  const delta = Number(req.body?.delta || req.body?.amount || 0);
  if (!u) return res.status(400).json({ error: "username required" });
  adjustWallet(u, delta, "admin_adjust")
    .then(r => res.json({ success: true, balance: r.balance }))
    .catch(() => res.status(500).json({ error: "failed" }));
}
app.post("/api/wallet/adjust", verifyAdminToken, walletAdjustHandler);
app.post("/api/admin/wallet/adjust", verifyAdminToken, walletAdjustHandler);

app.post("/api/wallet/credit", verifyAdminToken, async (req, res) => {
  const u = String(req.body?.username || req.body?.user || req.body?.name || "").toUpperCase();
  const amount = Number(req.body?.amount || 0);
  if (!u) return res.status(400).json({ error: "username required" });
  try {
    const r = await adjustWallet(u, amount, "admin_credit");
    res.json({ success: true, balance: r.balance });
  } catch {
    res.status(500).json({ error: "failed" });
  }
});
app.get("/api/wallet/balance", verifyAdminToken, async (req, res) => {
  const u = String(req.query.user || "").toUpperCase();
  const w = await getWallet(u);
  res.json({ balance: Number(w.balance || 0) });
});

// ✅ public wallet read; now uses persistent wallet and viewer cookie
app.get("/api/wallet/me", async (req, res) => {
  const cookieName = String(req.cookies?.viewer || "").toUpperCase();
  const qName      = String(req.query.viewer || "").toUpperCase();
  const username   = cookieName || qName || "";
  const w = await getWallet(username);
  res.json({ username, wallet: { balance: Number(w.balance || 0) } });
});

/* ===================== Viewer session (unified login) ===================== */
// Register (optional endpoint – safe to keep even if your UI logs in directly)
app.post("/api/viewer/register", async (req, res) => {
  try {
    const name = U(req.body?.username || req.body?.user || "");
    const pwd  = String(req.body?.password || "");
    if (!name || !pwd) return res.status(400).json({ error: "missing_credentials" });

    const exists = await userFind(name);
    if (exists) return res.status(409).json({ error: "user_exists" });

    const passHash = await bcrypt.hash(pwd, 10);
    await userCreate(name, passHash);

    res.cookie("viewer", name, {
      httpOnly: false, sameSite: "lax",
      secure: NODE_ENV === "production",
      maxAge: 1000*60*60*24*30, path: "/",
    });

    await grantSignupBonusIfNeeded(name);
    const w = await getWallet(name);
    res.json({ success: true, username: name, wallet: { balance: Number(w.balance||0) } });
  } catch (e) {
    console.error("[register] error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// Normal player login; elevates to admin ONLY if username whitelisted AND password matches ADMIN_PASS.
// Also makes sure signup bonus is granted once (and never removed).
app.post("/api/viewer/login", async (req, res) => {
  try {
    const name = String(req.body?.username || req.body?.user || "").trim().toUpperCase();
    const pwd  = String(req.body?.password || "");

    if (!name) return res.status(400).json({ error: "username required" });

    // Optional: if a stored password exists, enforce it; otherwise allow legacy logins.
    const existing = await userFind(name);
    if (existing?.passHash) {
      const ok = await bcrypt.compare(pwd, existing.passHash);
      if (!ok) return res.status(401).json({ error: "invalid_login" });
    }

    res.cookie("viewer", name, {
      httpOnly: false,
      sameSite: "lax",
      secure: NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 30, // 30d
      path: "/",
    });

    const elevate = isAdminName(name) && pwd === ADMIN_PASS;
    if (elevate) setAdminCookie(res, name);

    // One-time bonus (no-op if already granted)
    await grantSignupBonusIfNeeded(name);

    const w = await getWallet(name);
    res.json({ success: true, username: name, admin: elevate, wallet: { balance: Number(w.balance||0) } });
  } catch (e) {
    console.error("[login] error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.get("/api/viewer/me", async (req, res) => {
  const cookieName = String(req.cookies?.viewer || "").toUpperCase();
  const qName = String(req.query.viewer || "").toUpperCase();
  const username = cookieName || qName || "";
  const w = await getWallet(username);

  const admin = hasValidAdminCookie(req); // don't auto-elevate here
  res.json({
    username,
    anon: !username,
    admin,
    wallet: { balance: Number(w.balance||0) },
    flags: { pvpEntriesOpen: !!memory.flags.pvpEntriesOpen }
  });
});
app.post("/api/viewer/logout", (req, res) => {
  res.clearCookie("viewer", { path: "/" });
  res.clearCookie("admin_token", { path: "/" });
  res.json({ success: true });
});

/* ===================== Deposits / Orders ===================== */
app.get("/api/deposits/pending", verifyAdminToken, (req, res) => res.json({ orders: memory.deposits }));
app.post("/api/deposits/:id/approve", verifyAdminToken, (req, res) => { const id = String(req.params.id); memory.deposits = memory.deposits.filter(o => String(o.id||o._id) !== id); res.json({ success: true }); });
app.post("/api/deposits/:id/reject", verifyAdminToken, (req, res) => { const id = String(req.params.id); memory.deposits = memory.deposits.filter(o => String(o.id||o._id) !== id); res.json({ success: true }); });

// accept client submit
app.post("/api/lbx/orders", (req, res) => {
  const o = req.body || {};
  o._id = o._id || ("ORD-" + Math.random().toString(36).slice(0,10).toUpperCase());
  o.status = "pending";
  o.ts = o.ts || Date.now();
  memory.deposits.unshift(o);
  res.json({ success: true, order: o });
});

/* ===================== Raffles / Giveaways (admin shims) ===================== */
function ensureRaffle(rid){
  let r = (memory.raffles||[]).find(x => x.rid === rid);
  if (!r) { r = { rid, title: rid, open:true, createdAt: Date.now(), entries: [], winner:null }; memory.raffles.unshift(r); }
  return r;
}
app.get("/api/admin/raffles/:rid/entries", verifyAdminToken, (req,res)=>{
  const rid = String(req.params.rid||"").toUpperCase(); const r = ensureRaffle(rid);
  res.json({ rid: r.rid, title: r.title, open: !!r.open, winner: r.winner||null, entries: r.entries||[] });
});
app.post("/api/admin/raffles/:rid/entries", verifyAdminToken, (req,res)=>{
  const rid = String(req.params.rid||"").toUpperCase(); const user = String(req.body?.user||req.body?.username||"").toUpperCase();
  if (!user) return res.status(400).json({ error: "user required" });
  const r = ensureRaffle(rid); r.entries = r.entries || [];
  if (!r.entries.some(e => String(e.user).toUpperCase()===user)) r.entries.push({ user, ts: Date.now() });
  res.json({ success:true });
});
app.get("/api/admin/giveaways/:gid/entries", verifyAdminToken, (req,res)=>{
  const rid = String(req.params.gid||"").toUpperCase(); const r = ensureRaffle(rid);
  res.json({ rid: r.rid, title: r.title, open: !!r.open, winner: r.winner||null, entries: r.entries||[] });
});
app.post("/api/admin/giveaways/:gid/entries", verifyAdminToken, (req,res)=>{
  const rid = String(req.params.gid||"").toUpperCase(); const user = String(req.body?.user||req.body?.username||"").toUpperCase();
  if (!user) return res.status(400).json({ error: "user required" });
  const r = ensureRaffle(rid); r.entries = r.entries || [];
  if (!r.entries.some(e => String(e.user).toUpperCase()===user)) r.entries.push({ user, ts: Date.now() });
  res.json({ success:true });
});

/* ===================== Prize Claims ===================== */
app.post("/api/prize-claims", (req, res) => {
  const b = req.body || {};
  const claim = {
    _id: String(Date.now()),
    user: String(b.user || "").toUpperCase(),
    raffle: String(b.raffle || "GLOBAL"),
    asset: String(b.asset || ""),
    wallet: String(b.wallet || ""),
    created: Date.now(),
    status: "pending"
  };
  if (!claim.user) return res.status(400).json({ error: "user required" });
  memory.claims.unshift(claim);
  res.json({ success: true, claim });
});
app.get("/api/prize-claims", verifyAdminToken, (req, res) => {
  const status = String(req.query.status || "pending").toLowerCase();
  let list = memory.claims || [];
  if (status !== "all") list = list.filter(c => c.status === status);
  res.json({ claims: list });
});
app.post("/api/prize-claims/:id/status", verifyAdminToken, (req, res) => {
  const id = String(req.params.id);
  const status = String(req.body?.status || "").toLowerCase();
  if (!["approved","rejected","pending"].includes(status)) return res.status(400).json({ error: "bad status" });
  const i = (memory.claims || []).findIndex(c => String(c._id) === id);
  if (i < 0) return res.json({ success: false });
  memory.claims[i].status = status;
  res.json({ success: true });
});

/* ===================== Leaderboard ===================== */
app.post("/api/leaderboard/upsert", verifyAdminToken, async (req, res) => {
  const user = String(req.body?.user || req.body?.username || "").toUpperCase();
  const delta = Number(req.body?.deltaTournamentPoints || 0);
  const actions = Array.isArray(req.body?.actions) ? req.body.actions : [];
  if (!user) return res.status(400).json({ error: "username required" });

  try {
    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("profiles");
      const r = await col.findOneAndUpdate(
        { username: user },
        {
          $setOnInsert: { username: user, tournamentPoints: 0, bonusHuntPoints: 0 },
          $inc: { tournamentPoints: delta },
          $push: { history: { ts: new Date(), mode: "Lucky7", added: delta, actions } }
        },
        { upsert: true, returnDocument: "after" }
      );
      return res.json({ success: true, profile: r.value });
    } else {
      const p = memory.profiles[user] || { username: user, tournamentPoints: 0, bonusHuntPoints: 0, history: [] };
      p.tournamentPoints = Number(p.tournamentPoints || 0) + delta;
      p.history.unshift({ ts: Date.now(), mode: "Lucky7", added: delta, actions });
      memory.profiles[user] = p;
      return res.json({ success: true, profile: p });
    }
  } catch (e) {
    console.error("[LEADERBOARD] upsert failed", e);
    return res.status(500).json({ error: "failed" });
  }
});
app.post("/api/admin/leaderboard/rebuild", verifyAdminToken, (req,res)=> res.json({ success:true }));

/* ===================== PVP (entries + toggle) ===================== */

// Public: check if entries are open
app.get("/api/pvp/entries/open", (req,res)=>{
  res.json({ open: !!memory.flags.pvpEntriesOpen });
});

// Admin: open/close entries
app.post("/api/admin/pvp/entries/open", verifyAdminToken, (req,res)=>{
  const open = !!req.body?.open;
  memory.flags.pvpEntriesOpen = open;
  res.json({ success:true, open });
});

app.post("/api/pvp/entries", async (req, res) => {
  const username = String(req.body?.username || req.body?.user || "").trim().toUpperCase();
  const side     = String(req.body?.side || "").trim().toUpperCase();
  const game     = String(req.body?.game || "").trim();
  if (!username) return res.status(400).json({ error: "username required" });

  // respect admin toggle
  if (!memory.flags.pvpEntriesOpen) return res.status(403).json({ error: "entries_closed" });

  const doc = { username, side: side==="WEST" ? "WEST" : "EAST", game, status: "pending", ts: new Date() };
  try {
    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("pvp_entries");
      const existing = await col.findOne({ username });
      if (existing) return res.status(409).json({ error: "duplicate", entry: existing });
      const r = await col.insertOne(doc);
      const saved = await col.findOne({ _id: r.insertedId });
      return res.json({ success: true, entry: saved });
    } else {
      const exists = memory.pvpEntries.find(e => e.username === username);
      if (exists) return res.status(409).json({ error: "duplicate", entry: exists });
      const saved = { _id: String(Date.now()), ...doc };
      memory.pvpEntries.push(saved);
      return res.json({ success: true, entry: saved });
    }
  } catch (e) {
    console.error("[PVP] save failed", e);
    return res.status(500).json({ error: "save failed" });
  }
});
app.get("/api/pvp/entries", verifyAdminToken, async (req, res) => {
  try {
    if (globalThis.__dbReady) {
      const list = await globalThis.__db.collection("pvp_entries").find().sort({ ts: -1 }).toArray();
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
app.post("/api/pvp/entries/:id/status", verifyAdminToken, async (req, res) => {
  const status = String(req.body?.status || "").toLowerCase();
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

/* ===================== PVP Bracket + LIVE BG/Bonus (kept) ===================== */
function nowMs(){ return Date.now(); }
function emptyRound(n){
  return Array.from({length:n}, (_,i)=>({
    id: `m_${Math.random().toString(36).slice(2,8)}_${i}`,
    left:  { name:"", img:"", score:null },
    right: { name:"", img:"", score:null },
    status: "pending", winner: null, game: ""
  }));
}
function buildEmptySide(size){
  const firstRound = size/4;
  const r1 = emptyRound(firstRound);
  const r2 = emptyRound(Math.max(1, firstRound/2));
  const r3 = emptyRound(1);
  return [r1, r2, r3];
}
function nextIndex(i){ return Math.floor(i/2); }
function putIntoSlot(match, slot, player){
  if (slot==="left") match.left = { ...(match.left||{}), ...player };
  else match.right = { ...(match.right||{}), ...player };
}

async function getBracket(){
  if (globalThis.__dbReady){
    const col = globalThis.__db.collection("pvp_bracket");
    const doc = await col.findOne({ _id: "active" });
    return doc?.builder || null;
  }
  return memory.pvpBracket || null;
}
async function saveBracket(builder){
  builder.lastUpdated = nowMs();
  if (globalThis.__dbReady){
    const col = globalThis.__db.collection("pvp_bracket");
    await col.updateOne({ _id: "active" }, { $set: { builder } }, { upsert: true });
  } else {
    memory.pvpBracket = builder;
  }
  memory.live.pvp = builder;
  return builder;
}

app.get("/api/pvp/bracket", async (req, res) => {
  try { const builder = await getBracket(); res.json({ builder: builder || null }); }
  catch (e) { console.error("[PVP] bracket get failed", e); res.status(500).json({ error: "failed" }); }
});
app.post("/api/pvp/bracket", verifyAdminToken, async (req, res) => {
  try {
    if (req.body?.builder) { const saved = await saveBracket(req.body.builder); return res.json({ success: true, builder: saved }); }
    const { size, eastSeeds = [], westSeeds = [], games = [], meta = {} } = req.body || {};
    const bracketSize = (size===32||size===16) ? size : 16;
    const east = buildEmptySide(bracketSize);
    const west = buildEmptySide(bracketSize);
    const finals = [ emptyRound(1) ];
    const fillSide = (round0, seeds) => {
      for (let i=0; i<round0.length; i++){
        const L = seeds[i*2]   || { name: "" };
        const R = seeds[i*2+1] || { name: "" };
        round0[i].left.name  = (L.name||"").toUpperCase();
        round0[i].left.img   = L.img||"";
        round0[i].right.name = (R.name||"").toUpperCase();
        round0[i].right.img  = R.img||"";
      }
    };
    fillSide(east[0], eastSeeds); fillSide(west[0], westSeeds);
    if (Array.isArray(games) && games.length){
      const assign = (round0) => { for (let i=0;i<round0.length;i++){ const g = games[i % games.length]; round0[i].game = (g && (g.title || g.name || g)) || ""; } };
      assign(east[0]); assign(west[0]);
    }
    const saved = await saveBracket({
      lastUpdated: nowMs(),
      bracket: {
        size: bracketSize, east, west, finals,
        meta: { bestOf: 1, ...meta },
        cursor: { phase: "east", roundIndex: 0, matchIndex: 0 },
        champion: null
      }
    });
    res.json({ success: true, builder: saved });
  } catch (e) { console.error("[PVP] bracket build failed", e); res.status(500).json({ error: "failed" }); }
});
app.patch("/api/pvp/bracket/slot", verifyAdminToken, async (req, res) => {
  try {
    const { phase, roundIndex, matchIndex, side, name, img } = req.body || {};
    const b = await getBracket(); if (!b || !b.bracket) return res.status(404).json({ error: "no bracket" });
    const col = (phase==="east") ? b.bracket.east : (phase==="west") ? b.bracket.west : (phase==="finals") ? b.bracket.finals : null;
    if (!col) return res.status(400).json({ error: "bad phase" });
    const round = col[roundIndex|0]; const match = round && round[matchIndex|0];
    if (!match) return res.status(400).json({ error: "bad index" });
    const slot = side==="left" ? match.left : match.right;
    if (!slot) return res.status(400).json({ error: "bad side" });
    if (typeof name === "string") slot.name = name.toUpperCase();
    if (typeof img === "string")  slot.img  = img;
    await saveBracket(b);
    res.json({ success: true });
  } catch (e) { console.error("[PVP] slot patch failed", e); res.status(500).json({ error: "failed" }); }
});
app.post("/api/pvp/bracket/progress", verifyAdminToken, async (req, res) => {
  try {
    const { phase, roundIndex, matchIndex, winner, leftScore=null, rightScore=null } = req.body || {};
    if (!["L","R"].includes((winner||"").toUpperCase())) return res.status(400).json({ error: "winner must be L or R" });
    const b = await getBracket(); if (!b || !b.bracket) return res.status(404).json({ error: "no bracket" });
    const sideArr = phase==="east" ? b.bracket.east : phase==="west" ? b.bracket.west : phase==="finals" ? b.bracket.finals : null;
    if (!sideArr) return res.status(400).json({ error: "bad phase" });
    const rIdx = roundIndex|0, mIdx = matchIndex|0;
    const round = sideArr[rIdx]; if (!round) return res.status(400).json({ error: "bad round index" });
    const match = round[mIdx];   if (!match) return res.status(400).json({ error: "bad match index" });
    if (leftScore !== null)  match.left.score  = Number(leftScore);
    if (rightScore !== null) match.right.score = Number(rightScore);
    match.winner = winner.toUpperCase();
    match.status = "done";
    const adv = (winner.toUpperCase()==="L") ? match.left : match.right;
    const advPlayer = { name: adv.name || "", img: adv.img || "" };
    const lastRoundIndex = sideArr.length - 1;
    if (rIdx < lastRoundIndex){
      const nextRound = sideArr[rIdx + 1];
      const target = nextRound[nextIndex(mIdx)];
      const slot = (mIdx % 2 === 0) ? "left" : "right";
      putIntoSlot(target, slot, advPlayer);
    } else {
      const gf = (b.bracket.finals && b.bracket.finals[0] && b.bracket.finals[0][0]) ? b.bracket.finals[0][0] : null;
      if (gf){
        if (phase==="east") putIntoSlot(gf, "left", advPlayer);
        if (phase==="west") putIntoSlot(gf, "right", advPlayer);
        if (phase==="finals"){ b.bracket.champion = { name: advPlayer.name }; }
      }
    }
    if (b.bracket.cursor && b.bracket.cursor.phase===phase && (b.bracket.cursor.roundIndex|0)===rIdx && (b.bracket.cursor.matchIndex|0)===mIdx){
      const nxt = (function findNextPending(br){
        const order = [["east"],["west"],["finals"]];
        for (const [ph] of order){
          const sideArr2 = br[ph]; if (!sideArr2) continue;
          for (let r=0;r<sideArr2.length;r++){
            const round2 = sideArr2[r] || [];
            for (let m=0;m<round2.length;m++){
              if (round2[m].status!=="done") return { phase: ph, roundIndex: r, matchIndex: m };
            }
          }
        }
        return null;
      })(b.bracket);
      if (nxt) b.bracket.cursor = nxt;
    }
    await saveBracket(b);
    res.json({ success: true, builder: b });
  } catch (e) { console.error("[PVP] progress failed", e); res.status(500).json({ error: "failed" }); }
});
app.post("/api/pvp/bracket/reset", verifyAdminToken, async (req, res) => {
  try {
    const b = await getBracket();
    if (!b || !b.bracket) return res.status(404).json({ error: "no bracket" });
    const resetSide = (arr) => {
      for (let r=0;r<arr.length;r++){
        for (let m=0;m<arr[r].length;m++){
          const mm = arr[r][m];
          if (r===0){
            mm.status = "pending"; mm.winner=null;
            mm.left.score=null; mm.right.score=null;
          }else{
            arr[r][m] = { ...mm, left:{name:"",img:"",score:null}, right:{name:"",img:"",score:null}, status:"pending", winner:null };
          }
        }
      }
    };
    resetSide(b.bracket.east); resetSide(b.bracket.west);
    if (b.bracket.finals && b.bracket.finals[0] && b.bracket.finals[0][0]){
      b.bracket.finals[0][0] = {
        id: b.bracket.finals[0][0].id || `gf_${Math.random().toString(36).slice(2,8)}`,
        left:{name:"",img:"",score:null}, right:{name:"",img:"",score:null},
        status:"pending", winner:null, game: b.bracket.finals[0][0].game || ""
      };
    }
    b.bracket.champion = null;
    b.bracket.cursor = { phase:"east", roundIndex:0, matchIndex:0 };
    await saveBracket(b);
    res.json({ success:true });
  } catch (e) { console.error("[PVP] reset failed", e); res.status(500).json({ error: "failed" }); }
});

/* ===================== Unified LIVE for BG/Bonus + markets ===================== */
async function getLiveBuilder(key){
  if (globalThis.__dbReady){
    const col = globalThis.__db.collection("live_feeds");
    const doc = await col.findOne({ _id: key });
    return doc?.builder || null;
  }
  return memory.live?.[key] || null;
}
async function saveLiveBuilder(key, builder){
  builder.lastUpdated = nowMs();
  if (globalThis.__dbReady){
    const col = globalThis.__db.collection("live_feeds");
    await col.updateOne({ _id: key }, { $set: { builder } }, { upsert: true });
  } else {
    if (!memory.live) memory.live = {};
    memory.live[key] = builder;
  }
  return builder;
}
app.get("/api/battleground/live", async (req,res)=>{ try{ const b = await getLiveBuilder("battleground"); res.json({ builder: b || null }); } catch(e){ console.error("[BG] live get failed", e); res.status(500).json({ error:"failed" }); }});
app.post("/api/battleground/builder", verifyAdminToken, async (req,res)=>{
  try{
    const raw = (req.body && typeof req.body==='object') ? req.body : null;
    const b = raw?.builder ?? raw;
    if (!b || !Array.isArray(b.matches)) return res.status(400).json({ error:"invalid builder" });
    await saveLiveBuilder("battleground", b);

    // auto-create TOTAL ROUNDS BANDS draft from match count
    const m = Array.isArray(b.matches) ? b.matches.length : 0;
    if (m > 0){
      const bandsDraft = buildTotalRoundsBandsDraft(m);
      upsertDraft(bandsDraft);
    }
    res.json({ success:true, autoDraft: m>0 ? true : false });
  }catch(e){ console.error("[BG] publish failed", e); res.status(500).json({ error:"failed" }); }
});

// Alias: /api/battleground/publish  → same as /api/battleground/builder
app.post("/api/battleground/publish", verifyAdminToken, async (req, res) => {
  try {
    const raw = (req.body && typeof req.body === "object") ? req.body : null;
    const b   = raw?.builder ?? raw;
    if (!b || !Array.isArray(b.matches)) return res.status(400).json({ error: "invalid builder" });

    await saveLiveBuilder("battleground", b);

    const m = Array.isArray(b.matches) ? b.matches.length : 0;
    if (m > 0) {
      const bandsDraft = buildTotalRoundsBandsDraft(m);
      upsertDraft(bandsDraft);
    }
    res.json({ success: true });
  } catch (e) {
    console.error("[BG] publish (alias) failed", e);
    res.status(500).json({ error: "failed" });
  }
});

app.get("/api/bonus-hunt/live", async (req,res)=>{ try{ const b = await getLiveBuilder("bonus"); res.json({ builder: b || null }); }catch(e){ console.error("[BH] live get failed", e); res.status(500).json({ error:"failed" }); }});
app.post("/api/bonus-hunt/builder", verifyAdminToken, async (req,res)=>{ try{ const raw = (req.body && typeof req.body==='object') ? req.body : null; const b = raw?.builder ?? raw; if (!b || !Array.isArray(b.games)) return res.status(400).json({ error:"invalid builder" }); await saveLiveBuilder("bonus", b); res.json({ success:true }); }catch(e){ console.error("[BH] publish failed", e); res.status(500).json({ error:"failed" }); }});

// Alias: /api/bonus-hunt/publish  → same as /api/bonus-hunt/builder
app.post("/api/bonus-hunt/publish", verifyAdminToken, async (req, res) => {
  try {
    const raw = (req.body && typeof req.body === "object") ? req.body : null;
    const b   = raw?.builder ?? raw;
    if (!b || !Array.isArray(b.games)) return res.status(400).json({ error: "invalid builder" });
    await saveLiveBuilder("bonus", b);
    res.json({ success: true });
  } catch (e) {
    console.error("[BH] publish (alias) failed", e);
    res.status(500).json({ error: "failed" });
  }
});

// Unified markets ping
app.get("/api/markets/unified", async (req, res) => {
  const bg = await getLiveBuilder("battleground");
  const bh = await getLiveBuilder("bonus");
  res.json({
    battleground: !!(bg && Array.isArray(bg.matches) && bg.matches.length),
    bonusHunt: !!(bh && Array.isArray(bh.games) && bh.games.length),
    meta: { ts: Date.now() }
  });
});

/* ===================== Bets Admin API (drafts/publish) ===================== */
const DEFAULT_BAND_ODDS = 2.50;

function buildTotalRoundsBandsDraft(matchCount){
  const m = Number(matchCount||0);
  const min = 2*m, max = 3*m;

  const bands = [
    { key:"A", from:min,       to:min+2,  label:`${min}–${min+2}.5` },
    { key:"B", from:min+3,     to:min+5,  label:`${min+3}–${min+5.5}`.replace(".5.5",".5") },
    { key:"C", from:min+6,     to:min+8,  label:`${min+6}–${min+8.5}`.replace(".5.5",".5") },
    { key:"D", from:Math.min(min+9, max), to:max, label:`${Math.min(min+9,max)}+` }
  ].filter(b => b.from <= b.to && b.from <= max);

  const today = new Date().toISOString().slice(0,10);
  const eventId = `BG-TRB-${m}-${today}`;

  const event = {
    kind: "battleground",
    eventTitle: `BG — Total Rounds Bands (Best of 3) — ${m} matches`,
    eventId,
    ts: Date.now(),
    picks: bands.map(b => ({
      id:`TRB-${b.from}-${b.to}`,
      market:"TOTAL_ROUNDS_BANDS",
      left:"TOTAL ROUNDS",
      right:`${m} MATCHES`,
      band: { from: b.from, to: b.to },
      pickName: b.label,
      odds: DEFAULT_BAND_ODDS
    }))
  };
  return event;
}
function upsertDraft(event){
  const id = event.eventId || event.id;
  if (!id) return false;
  const i = memory.betsDrafts.findIndex(x => (x.eventId||x.id)===id);
  if (i>=0) memory.betsDrafts[i] = { ...memory.betsDrafts[i], ...event };
  else memory.betsDrafts.unshift(event);
  return true;
}

app.post("/api/admin/bets", verifyAdminToken, (req,res)=>{
  const body = req.body || {};
  const id = String(body.eventId || body.id || "").trim() || ("EVT-"+Math.random().toString(36).slice(2,8).toUpperCase());
  const evt = {
    kind: String(body.kind || "battleground"),
    eventTitle: String(body.eventTitle || "Untitled Event"),
    eventId: id,
    picks: Array.isArray(body.picks) ? body.picks : [],
    ts: Date.now()
  };
  upsertDraft(evt);
  res.json({ ok:true, id });
});

app.get("/api/admin/bets", verifyAdminToken, (req,res)=>{
  const status = String(req.query.status || "draft").toLowerCase();
  const kind   = String(req.query.kind || "").toLowerCase();
  const src = status === "published" ? memory.betsPublished : memory.betsDrafts;
  let items = [...src];
  if (kind) items = items.filter(x => String(x.kind||"").toLowerCase()===kind);
  res.json({ ok:true, items });
});

app.post("/api/admin/bets/publish", verifyAdminToken, (req,res)=>{
  const { id, all=false, kind="" } = req.body || {};
  if (all){
    const k = String(kind||"").toLowerCase();
    const moving = k ? memory.betsDrafts.filter(x => String(x.kind||"").toLowerCase()===k) : [...memory.betsDrafts];
    moving.forEach(evt => {
      memory.betsPublished = [evt, ...memory.betsPublished.filter(x => (x.eventId||x.id)!==(evt.eventId||evt.id))];
    });
    memory.betsDrafts = memory.betsDrafts.filter(x => !moving.includes(x));
    return res.json({ ok:true, published: moving.length });
  } else {
    const i = memory.betsDrafts.findIndex(x => (x.eventId||x.id)===id);
    if (i<0) return res.status(404).json({ ok:false, error:"not found" });
    const evt = memory.betsDrafts[i];
    memory.betsDrafts.splice(i,1);
    memory.betsPublished = [evt, ...memory.betsPublished.filter(x => (x.eventId||x.id)!==(evt.eventId||evt.id))];
    return res.json({ ok:true, id: (evt.eventId||evt.id) });
  }
});

// Shim: POST /api/bets/publish  (mirrors /api/admin/bets/publish)
app.post("/api/bets/publish", verifyAdminToken, (req, res) => {
  const { id, all = false, kind = "" } = req.body || {};
  if (all) {
    const k = String(kind || "").toLowerCase();
    const moving = k
      ? memory.betsDrafts.filter(x => String(x.kind || "").toLowerCase() === k)
      : [...memory.betsDrafts];

    moving.forEach(evt => {
      memory.betsPublished = [
        evt,
        ...memory.betsPublished.filter(x => (x.eventId || x.id) !== (evt.eventId || evt.id))
      ];
    });

    memory.betsDrafts = memory.betsDrafts.filter(x => !moving.includes(x));
    return res.json({ ok: true, published: moving.length });
  } else {
    const i = memory.betsDrafts.findIndex(x => (x.eventId || x.id) === id);
    if (i < 0) return res.status(404).json({ ok: false, error: "not found" });
    const evt = memory.betsDrafts[i];
    memory.betsDrafts.splice(i, 1);
    memory.betsPublished = [
      evt,
      ...memory.betsPublished.filter(x => (x.eventId || x.id) !== (evt.eventId || evt.id))
    ];
    return res.json({ ok: true, id: (evt.eventId || evt.id) });
  }
});

// Public read for “live bets”
app.get("/api/bets/live", (req,res)=>{
  const kind = String(req.query.kind || "").toLowerCase();
  let items = [...memory.betsPublished];
  if (kind) items = items.filter(x => String(x.kind||"").toLowerCase()===kind);
  res.json({ ok:true, items, ts: Date.now() });
});

// Shim: GET /api/bets/published  (same shape as /api/bets/live)
app.get("/api/bets/published", (req, res) => {
  const kind = String(req.query.kind || "").toLowerCase();
  let items = [...memory.betsPublished];
  if (kind) items = items.filter(x => String(x.kind || "").toLowerCase() === kind);
  res.json({ ok: true, items, ts: Date.now() });
});

/* ===================== 404 / Error ===================== */
app.use((req, res) => res.status(404).send("Not found."));
app.use((err, req, res, next) => {
  console.error("[ERROR]", err?.stack || err);
  if (req.path.startsWith("/api")) return res.status(500).json({ error: "Server error" });
  res.status(500).send("Server error");
});

/* ===================== Start + DB ===================== */
app.listen(PORT, HOST, () => {
  console.log(`[Server] http://${HOST}:${PORT} (${NODE_ENV}) PUBLIC_DIR=${PUBLIC_DIR}`);
  console.log(`[Server] HOME_INDEX=${HOME_INDEX} hasHome=${HAS_HOME}`);
  console.log(`[Server] ADMIN_LOGIN_FILE=${ADMIN_LOGIN_FILE || "(none)"} | ADMIN_HUB_FILE=${ADMIN_HUB_FILE || "(none)"}`);
  console.log(`[Server] Admin bypass: ${DISABLE_ADMIN_AUTH ? "ON" : "OFF"}`);
});

(async () => {
  if (!MONGO_URI) {
    if (!ALLOW_MEMORY_FALLBACK) console.warn("[DB] No MONGO_URI; memory mode disabled.");
    else console.warn("[DB] No MONGO_URI; running in MEMORY MODE.");
    return;
  }
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
