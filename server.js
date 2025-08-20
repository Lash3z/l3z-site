// server.js — homepage-first, admin aliases, JSON+form login
// + Wallet (Mongo + file fallback) with ledger + daily reward
// + Viewer session (cookie) + signup bonus
// + Promo admin + redeem (matches Admin Hub)
// + Admin raffle entry endpoints (matches Admin Hub)
// + PVP Entries + Bracket APIs
// + LIVE publish feeds for Battleground & Bonus Hunt
// + Shared leaderboard upsert
// + Production hardening (CORS, secrets, cookies)

import fs from "fs";
import os from "os";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

/* ===================== ENV ===================== */
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || "production";

const ADMIN_USER   = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS   = process.env.ADMIN_PASS;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const JWT_SECRET   = process.env.SECRET || ADMIN_SECRET;

const MONGO_URI = process.env.MONGO_URI || "";
const MONGO_DB  = process.env.MONGO_DB  || "lash3z";
const ALLOW_MEMORY_FALLBACK = (process.env.ALLOW_MEMORY_FALLBACK || "true") === "true";

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(s=>s.trim()).filter(Boolean);

// Wallet/rewards
const SIGNUP_BONUS = Number(process.env.SIGNUP_BONUS || 0);
const DAILY_REWARD_AMOUNT = Number(process.env.DAILY_REWARD_AMOUNT || 5);
const DAILY_REWARD_WINDOW_MS = 24 * 60 * 60 * 1000;

// File persistence fallback (so “server sync” doesn’t wipe balances without DB)
const STATE_PERSIST = (process.env.STATE_PERSIST ?? "true") === "true";
const STATE_CANDIDATES = [
  process.env.STATE_FILE && path.resolve(process.env.STATE_FILE),
  path.join(process.cwd(), ".data", "lash3z-state.json"),
  path.join(os.tmpdir(), "lash3z-state.json"),
].filter(Boolean);
let STATE_FILE = STATE_CANDIDATES[0];

// Fail fast in production if secrets are missing
if (NODE_ENV === "production" && (!ADMIN_USER || !ADMIN_PASS || !ADMIN_SECRET || !JWT_SECRET)) {
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

/* ===================== Memory (default values) ===================== */
const memory = {
  jackpot: { amount: 0, month: new Date().toISOString().slice(0,7), perSubAUD: 2.5, currency: "AUD" },
  rules: {
    lbx: { SUB_NEW: 10, SUB_RENEW: 5, SUB_GIFT_GIFTER_PER: 2, SUB_GIFT_RECIPIENT: 3 },
    caps: { eventLBXPerUserPerDay: 100 },
    jackpotPerSubAUD: 2.50, jackpotCurrency: "AUD", depositContributesJackpot: false
  },
  events: [],
  wallets: {},        // { USER: { balance, ledger[], signupBonusGrantedAt, lastDailyClaimAt } }
  raffles: [],
  claims: [],
  deposits: [],
  profiles: {},        // leaderboard/profiles in memory
  pvpEntries: [],      // entries (if DB not connected)
  pvpBracket: null,    // active PVP bracket/builder (if DB not connected)
  live: { pvp: null, battleground: null, bonus: null },

  // Promo codes + redemptions (fallback)
  promoCodes: [],
  promoRedemptions: [],
};

/* ===================== File persistence (fallback) ===================== */
let storageMode = "memory"; // "mongo" | "file" | "memory"
function ensureWritableStatePath() {
  for (const cand of STATE_CANDIDATES) {
    try {
      const dir = path.dirname(cand);
      fs.mkdirSync(dir, { recursive: true });
      const t = path.join(dir, ".write-test");
      fs.writeFileSync(t, "ok");
      fs.rmSync(t);
      STATE_FILE = cand;
      return true;
    } catch {}
  }
  return false;
}
let saveTimer = null;
const saveDelayMs = 500;
function scheduleSave() {
  if (storageMode !== "file" || !STATE_PERSIST) return;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      const data = JSON.stringify(memory, null, 2);
      fs.writeFileSync(STATE_FILE, data);
      console.log(`[PERSIST] state saved → ${STATE_FILE}`);
    } catch (e) {
      console.warn("[PERSIST] save failed:", e?.message || e);
    }
  }, saveDelayMs);
}
function loadStateIfPresent() {
  if (!STATE_PERSIST) return;
  try {
    if (existsSync(STATE_FILE)) {
      const text = fs.readFileSync(STATE_FILE, "utf8");
      const parsed = JSON.parse(text);
      Object.assign(memory, parsed || {});
      console.log(`[PERSIST] state loaded from ${STATE_FILE}`);
    }
  } catch (e) {
    console.warn("[PERSIST] load failed:", e?.message || e);
  }
}

/* ===================== App ===================== */
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

// Light security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "interest-cohort=()");
  next();
});

// Parsers
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// CORS (only /api)
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

/* ===================== JWT helpers (admin) ===================== */
function generateAdminToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: "12h" });
}
function verifyAdminToken(req, res, next) {
  const token = req.cookies?.admin_token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try { const decoded = jwt.verify(token, JWT_SECRET); req.adminUser = decoded.username; next(); }
  catch { return res.status(401).json({ error: "Unauthorized" }); }
}

/* ===================== Viewer helpers ===================== */
const U = (s) => String(s || "").trim().toUpperCase();
function requireViewer(req, res, next) {
  const cookieName = String(req.cookies?.viewer || "").toUpperCase();
  const qName = String(req.query.viewer || "").toUpperCase();
  const bName = String(req.body?.viewer || req.body?.username || "").toUpperCase();
  const name = cookieName || qName || bName;
  if (!name) return res.status(401).json({ ok: false, error: "LOGIN_REQUIRED" });
  req.viewer = name;
  next();
}
const nowISO = () => new Date().toISOString();

/* ===================== Admin auth (JSON or form) ===================== */
const loginHits = new Map(); // simple anti-bruteforce (per 10min window)
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
  const b = req.body || {};
  const username = (b.username || b.user || b.email || "").toString().trim();
  const password = (b.password || b.pass || b.pwd || "").toString();
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  if (username.toLowerCase() === ADMIN_USER && password === ADMIN_PASS) {
    res.cookie("admin_token", generateAdminToken(username.toLowerCase()), {
      httpOnly: true,
      sameSite: "strict",
      secure: NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 12,
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

/* ===================== Health/Home/Admin pages ===================== */
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
    db: !!globalThis.__dbReady,
    storageMode,
    stateFile: storageMode === "file" ? STATE_FILE : null
  });
});
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

// Admin aliases (/admin/<file>.html → /pages/dashboard/admin/<file>.html)
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
app.get("/logout", (req, res) => {
  res.clearCookie("admin_token", { path: "/" });
  res.redirect(302, "/");
});

// Static
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

/* =================================================================== */
/* ===================== WALLET / VIEWER SESSION ===================== */
/* =================================================================== */

// DB-backed (fallback to memory/file) wallet
async function getWallet(username) {
  const user = U(username);
  if (!user) return { username: "", balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null };

  if (globalThis.__dbReady) {
    const col = globalThis.__db.collection("wallets");
    const found = await col.findOne({ username: user });
    if (found) {
      return {
        username: user,
        balance: Number(found.balance || 0),
        ledger: Array.isArray(found.ledger) ? found.ledger : [],
        signupBonusGrantedAt: found.signupBonusGrantedAt ?? null,
        lastDailyClaimAt: found.lastDailyClaimAt ?? null
      };
    }
    const fresh = { username: user, balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null };
    await col.insertOne(fresh);
    return { username: user, balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null };
  }

  const w = memory.wallets[user] || { balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null };
  memory.wallets[user] = w;
  return {
    username: user,
    balance: Number(w.balance || 0),
    ledger: Array.isArray(w.ledger) ? w.ledger : [],
    signupBonusGrantedAt: w.signupBonusGrantedAt,
    lastDailyClaimAt: w.lastDailyClaimAt || null
  };
}
async function adjustWallet(username, delta, reason = "adjust") {
  const user = U(username);
  const amount = Number(delta || 0);
  if (!user || !Number.isFinite(amount)) return { ok: false, error: "bad_params" };

  if (globalThis.__dbReady) {
    try {
      const col = globalThis.__db.collection("wallets");
      const tx  = { ts: nowISO(), delta: amount, reason };
      const r = await col.findOneAndUpdate(
        { username: user },
        {
          $setOnInsert: { username: user, balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null },
          $inc: { balance: amount },
          $push: { ledger: tx }
        },
        { upsert: true, returnDocument: "after" }
      );
      return { ok: true, balance: Number(r.value?.balance || 0) };
    } catch (e) {
      console.warn("[wallet] mongo adjust failed, falling back:", e?.message || e);
    }
  }

  const w = memory.wallets[user] || { balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null };
  w.balance = Number(w.balance || 0) + amount;
  w.ledger.push({ ts: nowISO(), delta: amount, reason });
  memory.wallets[user] = w;
  scheduleSave();
  return { ok: true, balance: w.balance };
}
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
        $setOnInsert: { username: user, balance: 0, ledger: [], lastDailyClaimAt: null },
        $inc: { balance: bonus },
        $set: { signupBonusGrantedAt: new Date() },
        $push: { ledger: tx }
      },
      { upsert: true, returnDocument: "after" }
    );
    return { ok: true, balance: Number(r.value?.balance || 0) };
  }

  const w = memory.wallets[user] || { balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null };
  if (w.signupBonusGrantedAt) return { ok: true, skipped: true, balance: Number(w.balance || 0) };
  w.balance = Number(w.balance || 0) + bonus;
  w.signupBonusGrantedAt = new Date();
  w.ledger.push({ ts: nowISO(), delta: bonus, reason: "signup_bonus" });
  memory.wallets[user] = w;
  scheduleSave();
  return { ok: true, balance: w.balance };
}

// Viewer session
app.post("/api/viewer/register", async (req, res) => {
  try {
    const name = U(req.body?.username || req.body?.user || "");
    const pwd  = String(req.body?.password || "");
    if (!name || !pwd) return res.status(400).json({ error: "missing_credentials" });

    // lightweight local users (Mongo optional)
    if (globalThis.__dbReady) {
      const users = globalThis.__db.collection("users");
      const exists = await users.findOne({ username: name });
      if (exists) return res.status(409).json({ error: "user_exists" });
      await users.insertOne({ username: name, passHash: crypto.createHash("sha256").update(pwd).digest("hex"), createdAt: new Date() });
    }

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
app.post("/api/viewer/login", async (req, res) => {
  try {
    const name = U(req.body?.username || req.body?.user || "");
    const pwd  = String(req.body?.password || "");
    if (!name) return res.status(400).json({ error: "username required" });

    if (globalThis.__dbReady) {
      const users = globalThis.__db.collection("users");
      const rec = await users.findOne({ username: name });
      if (rec?.passHash) {
        const ok = rec.passHash === crypto.createHash("sha256").update(pwd).digest("hex");
        if (!ok) return res.status(401).json({ error: "invalid_login" });
      }
    }

    res.cookie("viewer", name, {
      httpOnly: false, sameSite: "lax",
      secure: NODE_ENV === "production",
      maxAge: 1000*60*60*24*30, path: "/",
    });

    await grantSignupBonusIfNeeded(name);

    const w = await getWallet(name);
    res.json({ success: true, username: name, wallet: { balance: Number(w.balance||0) } });
  } catch (e) {
    console.error("[login] error", e);
    res.status(500).json({ error: "server_error" });
  }
});
app.post("/api/viewer/logout", (req, res) => {
  res.clearCookie("viewer", { path: "/" });
  res.clearCookie("admin_token", { path: "/" });
  res.json({ success: true });
});

// Public wallet reads (uses viewer cookie or ?viewer=)
app.get("/api/wallet/me", async (req, res) => {
  const cookieName = String(req.cookies?.viewer || "").toUpperCase();
  const qName      = String(req.query.viewer || "").toUpperCase();
  const username   = cookieName || qName || "";
  const w = await getWallet(username);

  const last = w.lastDailyClaimAt ? new Date(w.lastDailyClaimAt).getTime() : 0;
  const rem  = Math.max(0, DAILY_REWARD_WINDOW_MS - (Date.now() - last));

  res.json({
    username,
    wallet: {
      balance: Number(w.balance || 0),
      ledger: Array.isArray(w.ledger) ? w.ledger : []
    },
    rewards: { daily: { amount: DAILY_REWARD_AMOUNT, remainingMs: rem } }
  });
});

// Admin wallet ops
app.post("/api/wallet/adjust", verifyAdminToken, (req, res) => {
  const u = String(req.body?.username || req.body?.user || req.body?.name || "").toUpperCase();
  const delta = Number(req.body?.delta || req.body?.amount || 0);
  const why = String(req.body?.reason || "admin_adjust");
  if (!u) return res.status(400).json({ error: "username required" });
  adjustWallet(u, delta, why)
    .then(r => r?.ok ? res.json({ success: true, balance: r.balance }) : res.status(500).json({ error: r.error || "failed" }))
    .catch(e => { console.error("[/api/wallet/adjust] error:", e); res.status(500).json({ error: "server_error" }); });
});
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

// Daily reward
async function claimDailyReward(username) {
  const user = U(username);
  if (!user) return { ok: false, error: "LOGIN_REQUIRED" };
  const now = Date.now();

  if (globalThis.__dbReady) {
    const col = globalThis.__db.collection("wallets");
    const doc = await col.findOne({ username: user });
    const last = doc?.lastDailyClaimAt ? new Date(doc.lastDailyClaimAt).getTime() : 0;
    const remaining = Math.max(0, DAILY_REWARD_WINDOW_MS - (now - last));
    if (remaining > 0) return { ok: false, error: "NOT_YET", remainingMs: remaining };

    await col.updateOne(
      { username: user },
      {
        $setOnInsert: { username: user, balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null },
        $set: { lastDailyClaimAt: new Date(now) },
        $inc: { balance: DAILY_REWARD_AMOUNT },
        $push: { ledger: { ts: new Date().toISOString(), delta: DAILY_REWARD_AMOUNT, reason: "DAILY_REWARD" } }
      },
      { upsert: true }
    );
    const w = await getWallet(user);
    return { ok: true, added: DAILY_REWARD_AMOUNT, balance: Number(w.balance || 0), nextInMs: DAILY_REWARD_WINDOW_MS };
  }

  const w = memory.wallets[user] || { balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null };
  memory.wallets[user] = w;
  const last = w.lastDailyClaimAt ? new Date(w.lastDailyClaimAt).getTime() : 0;
  const remaining = Math.max(0, DAILY_REWARD_WINDOW_MS - (now - last));
  if (remaining > 0) return { ok: false, error: "NOT_YET", remainingMs: remaining };

  w.balance = Number(w.balance || 0) + DAILY_REWARD_AMOUNT;
  w.lastDailyClaimAt = new Date(now);
  w.ledger.push({ ts: new Date().toISOString(), delta: DAILY_REWARD_AMOUNT, reason: "DAILY_REWARD" });
  scheduleSave();
  return { ok: true, added: DAILY_REWARD_AMOUNT, balance: Number(w.balance || 0), nextInMs: DAILY_REWARD_WINDOW_MS };
}
app.post("/api/rewards/daily", requireViewer, async (req, res) => {
  try {
    const r = await claimDailyReward(req.viewer);
    if (!r.ok && r.error === "NOT_YET") {
      return res.status(429).json({ ok: false, error: "NOT_YET", remainingMs: r.remainingMs });
    }
    if (!r.ok) return res.status(400).json({ ok: false, error: r.error || "FAILED" });
    res.json(r);
  } catch (e) {
    console.error("[daily_reward] error", e);
    res.status(500).json({ ok:false, error:"SERVER" });
  }
});
/* =================================================================== */
/* ============================ JACKPOT =============================== */
/* =================================================================== */

// Public: read current jackpot
app.get("/api/jackpot", (req, res) => {
  const j = memory.jackpot || { amount: 0, month: new Date().toISOString().slice(0,7), perSubAUD: 2.5, currency: "AUD" };
  res.json({
    ok: true,
    amount: Number(j.amount || 0),
    month: String(j.month || new Date().toISOString().slice(0,7)),
    perSubAUD: Number(j.perSubAUD || 2.5),
    currency: String(j.currency || "AUD"),
    ts: Date.now()
  });
});

// Admin: set jackpot fields
app.post("/api/admin/jackpot", verifyAdminToken, (req, res) => {
  const b = req.body || {};
  if (typeof b.amount === "number") memory.jackpot.amount = Number(b.amount);
  if (typeof b.perSubAUD === "number") memory.jackpot.perSubAUD = Number(b.perSubAUD);
  if (typeof b.currency === "string") memory.jackpot.currency = String(b.currency || "AUD");
  if (typeof b.month === "string") memory.jackpot.month = String(b.month);
  scheduleSave();
  res.json({ ok: true, jackpot: memory.jackpot });
});

// Admin: increment/decrement by delta
app.patch("/api/admin/jackpot/increment", verifyAdminToken, (req, res) => {
  const delta = Number(req.body?.delta || 0);
  memory.jackpot.amount = Number(memory.jackpot.amount || 0) + delta;
  scheduleSave();
  res.json({ ok: true, amount: memory.jackpot.amount });
});

/* =================================================================== */
/* ======================== DEPOSITS / ORDERS ======================== */
/* =================================================================== */

app.get("/api/deposits/pending", verifyAdminToken, (req, res) => res.json({ orders: memory.deposits }));
app.post("/api/deposits/:id/approve", verifyAdminToken, (req, res) => {
  const id = String(req.params.id);
  memory.deposits = memory.deposits.filter(o => String(o.id||o._id) !== id);
  scheduleSave();
  res.json({ success: true });
});
app.post("/api/deposits/:id/reject", verifyAdminToken, (req, res) => {
  const id = String(req.params.id);
  memory.deposits = memory.deposits.filter(o => String(o.id||o._id) !== id);
  scheduleSave();
  res.json({ success: true });
});

// accept client submit
app.post("/api/lbx/orders", (req, res) => {
  const o = req.body || {};
  o._id = o._id || ("ORD-" + Math.random().toString(36).slice(2,10).toUpperCase());
  o.status = "pending";
  o.ts = o.ts || Date.now();
  memory.deposits.unshift(o);
  scheduleSave();
  res.json({ success: true, order: o });
});

/* =================================================================== */
/* ===================== RAFFLES / GIVEAWAYS (admin) ================= */
/* =================================================================== */

function ensureRaffle(rid){
  let r = (memory.raffles||[]).find(x => x.rid === rid);
  if (!r) { r = { rid, title: rid, open:true, createdAt: Date.now(), entries: [], winner:null }; memory.raffles.unshift(r); scheduleSave(); }
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
  scheduleSave();
  res.json({ success:true });
});
// Giveaways alias
app.get("/api/admin/giveaways/:gid/entries", verifyAdminToken, (req,res)=>{
  const rid = String(req.params.gid||"").toUpperCase(); const r = ensureRaffle(rid);
  res.json({ rid: r.rid, title: r.title, open: !!r.open, winner: r.winner||null, entries: r.entries||[] });
});
app.post("/api/admin/giveaways/:gid/entries", verifyAdminToken, (req,res)=>{
  const rid = String(req.params.gid||"").toUpperCase(); const user = String(req.body?.user||req.body?.username||"").toUpperCase();
  if (!user) return res.status(400).json({ error: "user required" });
  const r = ensureRaffle(rid); r.entries = r.entries || [];
  if (!r.entries.some(e => String(e.user).toUpperCase()===user)) r.entries.push({ user, ts: Date.now() });
  scheduleSave();
  res.json({ success:true });
});

/* =================================================================== */
/* ============================ PROMO CODES ========================== */
/* =================================================================== */

// Helpers (shared with Admin Hub)
const __promoHits = new Map();
function tinyRateLimit(windowMs = 10_000) {
  return (req, res, next) => {
    const k = `${req.ip || "ip"}:redeem`;
    const now = Date.now();
    const last = __promoHits.get(k) || 0;
    if (now - last < windowMs) return res.status(429).json({ ok: false, error: "TOO_FAST" });
    __promoHits.set(k, now);
    next();
  };
}
const PROMO_ALLOWED_AMOUNTS = new Set([5,10,15,20,25,30]);
function normCode(s = "") {
  return String(s).trim().toUpperCase().replace(/\s+/g, "");
}

// Create single
app.post("/api/admin/promo/create", verifyAdminToken, async (req, res) => {
  try {
    let { code, amount, maxRedemptions=1, perUserLimit=1, expiresAt=null, notes="" } = req.body || {};
    amount = Number(amount);
    maxRedemptions = Number(maxRedemptions);
    perUserLimit = Number(perUserLimit);

    if (!PROMO_ALLOWED_AMOUNTS.has(amount)) return res.status(400).json({ ok:false, error:"INVALID_AMOUNT" });
    if (maxRedemptions < 1 || perUserLimit < 1) return res.status(400).json({ ok:false, error:"LIMITS_INVALID" });

    const now = new Date();
    const doc = {
      code: normCode(code || `L3Z-${amount}-${Math.random().toString(36).slice(2,8).toUpperCase()}`),
      amount,
      maxRedemptions,
      perUserLimit,
      redeemedCount: 0,
      active: true,
      expiresAt: expiresAt ? new Date(expiresAt) : null,
      createdBy: req.adminUser || "admin",
      notes: String(notes || ""),
      createdAt: now,
      updatedAt: now,
    };

    if (globalThis.__dbReady) {
      await globalThis.__db.collection("promo_codes").insertOne(doc);
    } else {
      if ((memory.promoCodes||[]).some(p => p.code === doc.code)) return res.status(409).json({ ok:false, error:"CODE_EXISTS" });
      memory.promoCodes.unshift(doc);
      scheduleSave();
    }
    res.json({ ok:true, code: doc.code, promo: doc });
  } catch (e) {
    if (e?.code === 11000) return res.status(409).json({ ok:false, error:"CODE_EXISTS" });
    console.error("[promo/create]", e);
    res.status(500).json({ ok:false, error:"SERVER" });
  }
});

// Batch generate
app.post("/api/admin/promo/generate", verifyAdminToken, async (req, res) => {
  try {
    let { prefix = "L3Z", amount, count, maxRedemptions=1, perUserLimit=1, expiresAt=null, notes="" } = req.body || {};
    amount = Number(amount);
    count = Math.min(5000, Number(count || 1));
    if (!PROMO_ALLOWED_AMOUNTS.has(amount)) return res.status(400).json({ ok:false, error:"INVALID_AMOUNT" });
    if (count < 1) return res.status(400).json({ ok:false, error:"COUNT_INVALID" });

    const now = new Date();
    const mkCode = () => `${normCode(prefix)}-${amount}-${crypto.randomBytes(6).toString("base64").replace(/[^A-Z0-9]/gi,"").slice(0,7).toUpperCase()}`;

    if (globalThis.__dbReady) {
      const pc = globalThis.__db.collection("promo_codes");
      const docs = Array.from({ length: count }).map(() => ({
        code: mkCode(),
        amount,
        maxRedemptions: Number(maxRedemptions),
        perUserLimit: Number(perUserLimit),
        redeemedCount: 0,
        active: true,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        createdBy: req.adminUser || "admin",
        notes: String(notes || ""),
        createdAt: now,
        updatedAt: now,
      }));
      await pc.insertMany(docs, { ordered: false });
      return res.json({ ok:true, generated: docs.length, sample: docs.slice(0,5).map(d=>d.code) });
    } else {
      const docs = [];
      for (let i=0;i<count;i++){
        let c; do { c = mkCode(); } while ((memory.promoCodes||[]).some(p => p.code === c));
        docs.push({
          code: c, amount,
          maxRedemptions: Number(maxRedemptions),
          perUserLimit: Number(perUserLimit),
          redeemedCount: 0,
          active: true,
          expiresAt: expiresAt ? new Date(expiresAt) : null,
          createdBy: req.adminUser || "admin",
          notes: String(notes || ""),
          createdAt: now,
          updatedAt: now,
        });
      }
      memory.promoCodes = [...docs, ...(memory.promoCodes||[])];
      scheduleSave();
      return res.json({ ok:true, generated: docs.length, sample: docs.slice(0,5).map(d=>d.code) });
    }
  } catch (e) {
    console.error("[promo/generate]", e);
    res.status(500).json({ ok:false, error:"SERVER" });
  }
});

// List / disable
app.get("/api/admin/promo/list", verifyAdminToken, async (req, res) => {
  const only = "active" in req.query ? (req.query.active === "1") : null;
  if (globalThis.__dbReady) {
    const q = only === null ? {} : { active: only };
    const items = await globalThis.__db.collection("promo_codes").find(q).sort({ createdAt: -1 }).limit(500).toArray();
    return res.json({ ok:true, items });
  } else {
    let items = [...(memory.promoCodes||[])];
    if (only !== null) items = items.filter(p => !!p.active === only);
    return res.json({ ok:true, items });
  }
});
app.post("/api/admin/promo/disable", verifyAdminToken, async (req, res) => {
  const code = normCode(req.body?.code || "");
  if (!code) return res.status(400).json({ ok:false, error:"CODE_REQUIRED" });
  if (globalThis.__dbReady) {
    const r = await globalThis.__db.collection("promo_codes").updateOne({ code }, { $set: { active:false, updatedAt: new Date() } });
    return res.json({ ok:true, modified: r.modifiedCount });
  } else {
    const i = (memory.promoCodes||[]).findIndex(p => p.code === code);
    if (i >= 0) memory.promoCodes[i].active = false;
    scheduleSave();
    return res.json({ ok:true, modified: i >= 0 ? 1 : 0 });
  }
});

// Redeem (user)
app.post("/api/promo/redeem", requireViewer, tinyRateLimit(), async (req, res) => {
  try {
    const code = normCode(req.body?.code || "");
    if (!code) return res.status(400).json({ ok:false, error:"CODE_REQUIRED" });
    const username = req.viewer;
    const now = new Date();

    if (globalThis.__dbReady) {
      const pc = globalThis.__db.collection("promo_codes");
      const pr = globalThis.__db.collection("promo_redemptions");

      const promo = await pc.findOne({ code });
      if (!promo || !promo.active) return res.status(404).json({ ok:false, error:"INVALID_CODE" });
      if (promo.expiresAt && promo.expiresAt < now) return res.status(410).json({ ok:false, error:"EXPIRED" });
      if (promo.redeemedCount >= promo.maxRedemptions) return res.status(409).json({ ok:false, error:"DEPLETED" });

      const prior = await pr.countDocuments({ code, username });
      if (prior >= (promo.perUserLimit || 1)) return res.status(409).json({ ok:false, error:"PER_USER_LIMIT" });

      try {
        await pr.insertOne({ code, username, amount: Number(promo.amount||0), createdAt: now });
      } catch {
        return res.status(409).json({ ok:false, error:"ALREADY_REDEEMED" });
      }

      const up = await pc.updateOne(
        { _id: promo._id, redeemedCount: { $lt: promo.maxRedemptions } },
        { $inc: { redeemedCount: 1 }, $set: { updatedAt: now } }
      );
      if (up.modifiedCount !== 1) {
        await pr.deleteOne({ code, username }); // rollback
        return res.status(409).json({ ok:false, error:"DEPLETED" });
      }

      const credited = await adjustWallet(username, Number(promo.amount||0), `promo:${code}`);
      if (!credited?.ok) {
        await pc.updateOne({ _id: promo._id }, { $inc: { redeemedCount: -1 } });
        await pr.deleteOne({ code, username });
        return res.status(500).json({ ok:false, error:"CREDIT_FAILED" });
      }

      return res.json({ ok:true, added: Number(promo.amount||0), code, balance: credited.balance });
    }

    // FILE/MEMORY
    const promo = (memory.promoCodes||[]).find(p => p.code === code);
    if (!promo || !promo.active) return res.status(404).json({ ok:false, error:"INVALID_CODE" });
    if (promo.expiresAt && promo.expiresAt < now) return res.status(410).json({ ok:false, error:"EXPIRED" });
    if (promo.redeemedCount >= promo.maxRedemptions) return res.status(409).json({ ok:false, error:"DEPLETED" });

    const userClaims = (memory.promoRedemptions||[]).filter(r => r.code === code && r.username === username).length;
    if (userClaims >= (promo.perUserLimit || 1)) return res.status(409).json({ ok:false, error:"PER_USER_LIMIT" });

    // reserve
    promo.redeemedCount++;
    memory.promoRedemptions.unshift({ code, username, amount: Number(promo.amount||0), createdAt: now });

    const credited = await adjustWallet(username, Number(promo.amount||0), `promo:${code}`);
    if (!credited?.ok) {
      promo.redeemedCount = Math.max(0, promo.redeemedCount - 1);
      memory.promoRedemptions = (memory.promoRedemptions||[]).filter(r => !(r.code === code && r.username === username));
      scheduleSave();
      return res.status(500).json({ ok:false, error:"CREDIT_FAILED" });
    }
    scheduleSave();
    return res.json({ ok:true, added: Number(promo.amount||0), code, balance: credited.balance });
  } catch (e) {
    console.error("[promo/redeem]", e);
    res.status(500).json({ ok:false, error:"SERVER" });
  }
});

app.get("/api/promo/my-redemptions", requireViewer, async (req, res) => {
  const username = req.viewer;
  if (globalThis.__dbReady) {
    const rows = await globalThis.__db.collection("promo_redemptions")
      .find({ username }).sort({ createdAt: -1 }).limit(200).toArray();
    return res.json({ ok:true, items: rows });
  } else {
    const rows = (memory.promoRedemptions||[]).filter(r => r.username === username);
    return res.json({ ok:true, items: rows });
  }
});

/* =================================================================== */
/* ============================ LEADERBOARD ========================== */
/* =================================================================== */

const currentMonth = () => new Date().toISOString().slice(0, 7); // "YYYY-MM"

app.post("/api/leaderboard/upsert", verifyAdminToken, async (req, res) => {
  const user = String(req.body?.user || req.body?.username || "").toUpperCase();
  if (!user) return res.status(400).json({ error: "username required" });

  const mode = String(req.body?.mode || "tournament").toLowerCase();
  const fieldMap = {
    tournament: "tournamentPoints",
    bonus:      "bonusHuntPoints",
    pvp:        "pvpPoints",
    lucky7:     "lucky7Points",
  };
  const field = fieldMap[mode] || "tournamentPoints";

  const delta = Number(
    req.body?.delta ??
    req.body?.deltaTournamentPoints ??
    0
  );
  const actions = Array.isArray(req.body?.actions) ? req.body.actions : [];
  const month = String(req.body?.month || currentMonth());

  try {
    if (globalThis.__dbReady) {
      const db = globalThis.__db;

      // 1) Cumulative lifetime in profiles
      const profiles = db.collection("profiles");
      const cumInc = { [field]: delta };
      const r1 = await profiles.findOneAndUpdate(
        { username: user },
        {
          $setOnInsert: {
            username: user,
            tournamentPoints: 0,
            bonusHuntPoints:  0,
            pvpPoints:        0,
            lucky7Points:     0,
            history: []
          },
          $inc: cumInc,
          $push: { history: { ts: new Date(), mode, added: delta, actions } }
        },
        { upsert: true, returnDocument: "after" }
      );

      // 2) Monthly bucket in leaderboard_monthly
      const monthly = db.collection("leaderboard_monthly");
      const r2 = await monthly.findOneAndUpdate(
        { username: user, month },
        {
          $setOnInsert: {
            username: user,
            month,
            tournamentPoints: 0,
            bonusHuntPoints:  0,
            pvpPoints:        0,
            lucky7Points:     0,
            totalPoints:      0,
            history: []
          },
          $inc: { [field]: delta, totalPoints: delta },
          $push: { history: { ts: new Date(), mode, added: delta, actions } }
        },
        { upsert: true, returnDocument: "after" }
      );

      return res.json({
        success: true,
        cumulative: {
          username: r1.value.username,
          tournamentPoints: Number(r1.value.tournamentPoints || 0),
          bonusHuntPoints:  Number(r1.value.bonusHuntPoints  || 0),
          pvpPoints:        Number(r1.value.pvpPoints        || 0),
          lucky7Points:     Number(r1.value.lucky7Points     || 0)
        },
        monthly: {
          username: r2.value.username,
          month: r2.value.month,
          tournamentPoints: Number(r2.value.tournamentPoints || 0),
          bonusHuntPoints:  Number(r2.value.bonusHuntPoints  || 0),
          pvpPoints:        Number(r2.value.pvpPoints        || 0),
          lucky7Points:     Number(r2.value.lucky7Points     || 0),
          totalPoints:      Number(r2.value.totalPoints      || 0)
        }
      });
    } else {
      // ===== File/Memory fallback =====
      // cumulative
      const p = memory.profiles[user] || {
        username: user,
        tournamentPoints: 0,
        bonusHuntPoints:  0,
        pvpPoints:        0,
        lucky7Points:     0,
        history: []
      };
      p[field] = Number(p[field] || 0) + delta;
      p.history.unshift({ ts: Date.now(), mode, added: delta, actions });
      memory.profiles[user] = p;

      // monthly
      if (!memory.monthlyLB) memory.monthlyLB = {};
      memory.monthlyLB[month] = memory.monthlyLB[month] || {};
      const mrec = memory.monthlyLB[month][user] || {
        username: user,
        month,
        tournamentPoints: 0,
        bonusHuntPoints:  0,
        pvpPoints:        0,
        lucky7Points:     0,
        totalPoints:      0,
        history: []
      };
      mrec[field] = Number(mrec[field] || 0) + delta;
      mrec.totalPoints = Number(mrec.totalPoints || 0) + delta;
      mrec.history.unshift({ ts: Date.now(), mode, added: delta, actions });
      memory.monthlyLB[month][user] = mrec;

      scheduleSave();
      return res.json({
        success: true,
        cumulative: {
          username: p.username,
          tournamentPoints: p.tournamentPoints,
          bonusHuntPoints:  p.bonusHuntPoints,
          pvpPoints:        p.pvpPoints,
          lucky7Points:     p.lucky7Points
        },
        monthly: mrec
      });
    }
  } catch (e) {
    console.error("[LEADERBOARD] upsert failed", e);
    return res.status(500).json({ error: "failed" });
  }
});
app.get("/api/leaderboard/monthly", async (req, res) => {
  const month = String(req.query.month || currentMonth());
  const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 200)));

  try {
    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("leaderboard_monthly");
      const rows = await col.find({ month })
        .project({
          _id: 0, username: 1, month: 1,
          tournamentPoints: 1, bonusHuntPoints: 1, pvpPoints: 1, lucky7Points: 1,
          totalPoints: 1
        })
        .sort({ totalPoints: -1, tournamentPoints: -1, bonusHuntPoints: -1, pvpPoints: -1, lucky7Points: -1, username: 1 })
        .limit(limit)
        .toArray();

      // dense rank
      let lastKey = null, rank = 0;
      const ranked = rows.map((r, i) => {
        const key = `${r.totalPoints}|${r.tournamentPoints}|${r.bonusHuntPoints}|${r.pvpPoints}|${r.lucky7Points}`;
        if (key !== lastKey) { rank = i + 1; lastKey = key; }
        return { rank, ...r };
      });

      return res.json({ month, items: ranked });
    }

    // file/memory fallback
    const bucket = (memory.monthlyLB && memory.monthlyLB[month]) ? memory.monthlyLB[month] : {};
    const items = Object.values(bucket)
      .sort((a, b) =>
        (b.totalPoints || 0) - (a.totalPoints || 0) ||
        (b.tournamentPoints || 0) - (a.tournamentPoints || 0) ||
        (b.bonusHuntPoints || 0) - (a.bonusHuntPoints || 0) ||
        (b.pvpPoints || 0) - (a.pvpPoints || 0) ||
        (b.lucky7Points || 0) - (a.lucky7Points || 0) ||
        a.username.localeCompare(b.username)
      )
      .slice(0, limit);

    let lastKey = null, rank = 0;
    const ranked = items.map((r, i) => {
      const key = `${r.totalPoints}|${r.tournamentPoints}|${r.bonusHuntPoints}|${r.pvpPoints}|${r.lucky7Points}`;
      if (key !== lastKey) { rank = i + 1; lastKey = key; }
      return { rank, ...r };
    });

    return res.json({ month, items: ranked });
  } catch (e) {
    console.error("[LEADERBOARD] monthly list failed", e);
    return res.status(500).json({ error: "failed" });
  }
});
app.get("/api/leaderboard/overall", async (req, res) => {
  const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 200)));

  try {
    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("profiles");
      const rows = await col.aggregate([
        {
          $project: {
            _id: 0, username: 1,
            tournamentPoints: { $ifNull: ["$tournamentPoints", 0] },
            bonusHuntPoints:  { $ifNull: ["$bonusHuntPoints", 0] },
            pvpPoints:        { $ifNull: ["$pvpPoints", 0] },
            lucky7Points:     { $ifNull: ["$lucky7Points", 0] },
          }
        },
        {
          $addFields: {
            totalPoints: {
              $add: ["$tournamentPoints", "$bonusHuntPoints", "$pvpPoints", "$lucky7Points"]
            }
          }
        },
        { $sort: { totalPoints: -1, tournamentPoints: -1, bonusHuntPoints: -1, pvpPoints: -1, lucky7Points: -1, username: 1 } },
        { $limit: limit }
      ]).toArray();

      let lastKey = null, rank = 0;
      const ranked = rows.map((r, i) => {
        const key = `${r.totalPoints}|${r.tournamentPoints}|${r.bonusHuntPoints}|${r.pvpPoints}|${r.lucky7Points}`;
        if (key !== lastKey) { rank = i + 1; lastKey = key; }
        return { rank, ...r };
      });

      return res.json({ items: ranked });
    }

    // file/memory fallback
    const items = Object.values(memory.profiles || {})
      .map(p => ({
        username: p.username,
        tournamentPoints: Number(p.tournamentPoints || 0),
        bonusHuntPoints:  Number(p.bonusHuntPoints || 0),
        pvpPoints:        Number(p.pvpPoints || 0),
        lucky7Points:     Number(p.lucky7Points || 0),
      }))
      .map(r => ({ ...r,
        totalPoints: r.tournamentPoints + r.bonusHuntPoints + r.pvpPoints + r.lucky7Points
      }))
      .sort((a, b) =>
        (b.totalPoints || 0) - (a.totalPoints || 0) ||
        (b.tournamentPoints || 0) - (a.tournamentPoints || 0) ||
        (b.bonusHuntPoints || 0) - (a.bonusHuntPoints || 0) ||
        (b.pvpPoints || 0) - (a.pvpPoints || 0) ||
        (b.lucky7Points || 0) - (a.lucky7Points || 0) ||
        a.username.localeCompare(b.username)
      )
      .slice(0, limit);

    let lastKey = null, rank = 0;
    const ranked = items.map((r, i) => {
      const key = `${r.totalPoints}|${r.tournamentPoints}|${r.bonusHuntPoints}|${r.pvpPoints}|${r.lucky7Points}`;
      if (key !== lastKey) { rank = i + 1; lastKey = key; }
      return { rank, ...r };
    });

    return res.json({ items: ranked });
  } catch (e) {
    console.error("[LEADERBOARD] overall list failed", e);
    return res.status(500).json({ error: "failed" });
  }
});
/* =================================================================== */
/* ============================ PVP APIs ============================== */
/* =================================================================== */

// Public: check if entries are open (feature flag persisted in memory/file)
app.get("/api/pvp/entries/open", (req,res)=>{
  if (!memory.flags) memory.flags = { pvpEntriesOpen: true };
  res.json({ open: !!memory.flags.pvpEntriesOpen });
});

// Admin: open/close entries
app.post("/api/admin/pvp/entries/open", verifyAdminToken, (req,res)=>{
  const open = !!req.body?.open;
  if (!memory.flags) memory.flags = { pvpEntriesOpen: true };
  memory.flags.pvpEntriesOpen = open;
  scheduleSave?.();
  res.json({ success:true, open });
});

// Submit entry (public)
app.post("/api/pvp/entries", async (req, res) => {
  const username = String(req.body?.username || req.body?.user || "").trim().toUpperCase();
  const side     = String(req.body?.side || "").trim().toUpperCase();   // "EAST"/"WEST"
  const game     = String(req.body?.game || "").trim();
  if (!username) return res.status(400).json({ error: "username required" });

  if (memory.flags && memory.flags.pvpEntriesOpen === false) {
    return res.status(403).json({ error: "entries_closed" });
  }

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
      const exists = (memory.pvpEntries||[]).find(e => e.username === username);
      if (exists) return res.status(409).json({ error: "duplicate", entry: exists });
      const saved = { _id: String(Date.now()), ...doc };
      memory.pvpEntries = memory.pvpEntries || [];
      memory.pvpEntries.push(saved);
      scheduleSave?.();
      return res.json({ success: true, entry: saved });
    }
  } catch (e) {
    console.error("[PVP] save failed", e);
    return res.status(500).json({ error: "save failed" });
  }
});

// Admin: list entries
app.get("/api/pvp/entries", verifyAdminToken, async (req, res) => {
  try {
    if (globalThis.__dbReady) {
      const list = await globalThis.__db.collection("pvp_entries").find().sort({ ts: -1 }).toArray();
      return res.json({ entries: list });
    } else {
      const list = [...(memory.pvpEntries||[])].sort((a,b)=> new Date(b.ts) - new Date(a.ts));
      return res.json({ entries: list });
    }
  } catch (e) {
    console.error("[PVP] list failed", e);
    return res.status(500).json({ error: "list failed" });
  }
});

// Admin: update status
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
      const i = (memory.pvpEntries||[]).findIndex(e => e._id === id || e.username === id.toUpperCase());
      if (i < 0) return res.json({ success: false });
      memory.pvpEntries[i].status = status;
      scheduleSave?.();
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
      const before = (memory.pvpEntries||[]).length;
      memory.pvpEntries = (memory.pvpEntries||[]).filter(e => e._id !== id && e.username !== id.toUpperCase());
      scheduleSave?.();
      return res.json({ success: (memory.pvpEntries||[]).length !== before });
    }
  } catch (e) {
    console.error("[PVP] delete failed", e);
    return res.status(500).json({ error: "delete failed" });
  }
});

/* ====================== PVP Bracket (builder) ====================== */
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
  const firstRound = size/4; // e.g. 32→8, 16→4 (per side)
  const r1 = emptyRound(firstRound);
  const r2 = emptyRound(Math.max(1, firstRound/2)); // QF
  const r3 = emptyRound(1); // SF (side final)
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
    scheduleSave?.();
  }
  memory.live = memory.live || {};
  memory.live.pvp = builder; // mirror into unified live bus
  return builder;
}

// Read bracket
app.get("/api/pvp/bracket", async (req, res) => {
  try { const builder = await getBracket(); res.json({ builder: builder || null }); }
  catch (e) { console.error("[PVP] bracket get failed", e); res.status(500).json({ error: "failed" }); }
});

// Create/replace bracket
app.post("/api/pvp/bracket", verifyAdminToken, async (req, res) => {
  try {
    if (req.body?.builder) { const saved = await saveBracket(req.body.builder); return res.json({ success: true, builder: saved }); }
    const { size, eastSeeds = [], westSeeds = [], games = [], meta = {} } = req.body || {};
    const bracketSize = (size===32||size===16) ? size : 16;

    const east = buildEmptySide(bracketSize);
    const west = buildEmptySide(bracketSize);
    const finals = [ emptyRound(1) ]; // Grand Final

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
    fillSide(east[0], eastSeeds);
    fillSide(west[0], westSeeds);

    if (Array.isArray(games) && games.length){
      const assign = (round0) => {
        for (let i=0;i<round0.length;i++){
          const g = games[i % games.length];
          round0[i].game = (g && (g.title || g.name || g)) || "";
        }
      };
      assign(east[0]); assign(west[0]);
    }

    const saved = await saveBracket({
      lastUpdated: nowMs(),
      bracket: {
        size: bracketSize,
        east, west, finals,
        meta: { bestOf: 1, ...meta },
        cursor: { phase: "east", roundIndex: 0, matchIndex: 0 },
        champion: null
      }
    });

    res.json({ success: true, builder: saved });
  } catch (e) {
    console.error("[PVP] bracket build failed", e);
    res.status(500).json({ error: "failed" });
  }
});

// Edit a slot
app.patch("/api/pvp/bracket/slot", verifyAdminToken, async (req, res) => {
  try {
    const { phase, roundIndex, matchIndex, side, name, img } = req.body || {};
    const b = await getBracket(); if (!b || !b.bracket) return res.status(404).json({ error: "no bracket" });

    const col = (phase==="east") ? b.bracket.east
              : (phase==="west") ? b.bracket.west
              : (phase==="finals") ? b.bracket.finals
              : null;
    if (!col) return res.status(400).json({ error: "bad phase" });
    const round = col[roundIndex|0]; const match = round && round[matchIndex|0];
    if (!match) return res.status(400).json({ error: "bad index" });

    const slot = side==="left" ? match.left : match.right;
    if (!slot) return res.status(400).json({ error: "bad side" });
    if (typeof name === "string") slot.name = name.toUpperCase();
    if (typeof img === "string")  slot.img  = img;

    await saveBracket(b);
    res.json({ success: true });
  } catch (e) {
    console.error("[PVP] slot patch failed", e);
    res.status(500).json({ error: "failed" });
  }
});

// Progress winner
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
  } catch (e) {
    console.error("[PVP] progress failed", e);
    res.status(500).json({ error: "failed" });
  }
});

// Reset bracket (keep seeds)
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
  } catch (e) {
    console.error("[PVP] reset failed", e);
    res.status(500).json({ error: "failed" });
  }
});

/* =================================================================== */
/* ====================== LIVE FEEDS + MARKETS ======================= */
/* =================================================================== */

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
    memory.live = memory.live || {};
    memory.live[key] = builder;
    scheduleSave?.();
  }
  return builder;
}

// BG live (widgets)
app.get("/api/battleground/live", async (req,res)=>{
  try{ const b = await getLiveBuilder("battleground"); res.json({ builder: b || null }); }
  catch(e){ console.error("[BG] live get failed", e); res.status(500).json({ error:"failed" }); }
});

// BG publish from admin — accept {builder:…} or bare object
const DEFAULT_BAND_ODDS = 2.50;
function buildTotalRoundsBandsDraft(matchCount){
  const m = Number(matchCount||0);
  const min = 2*m, max = 3*m;

  const bands = [
    { key:"A", from:min,       to:min+2,  label:`${min}–${min+2}.5` },
    { key:"B", from:min+3,     to:min+5,  label:`${min+3}–${min+5.5}` },
    { key:"C", from:min+6,     to:min+8,  label:`${min+6}–${min+8.5}` },
    { key:"D", from:Math.min(min+9, max), to:max, label:`${Math.min(min+9,max)}+` }
  ].filter(b => b.from <= b.to && b.from <= max);

  const today = new Date().toISOString().slice(0,10);
  const eventId = `BG-TRB-${m}-${today}`;

  return {
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
}
function upsertDraft(event){
  const id = event.eventId || event.id;
  if (!id) return false;
  memory.betsDrafts = memory.betsDrafts || [];
  const i = memory.betsDrafts.findIndex(x => (x.eventId||x.id)===id);
  if (i>=0) memory.betsDrafts[i] = { ...memory.betsDrafts[i], ...event };
  else memory.betsDrafts.unshift(event);
  scheduleSave?.();
  return true;
}

app.post("/api/battleground/builder", verifyAdminToken, async (req,res)=>{
  try{
    const raw = (req.body && typeof req.body==='object') ? req.body : null;
    const b = raw?.builder ?? raw;
    if (!b || !Array.isArray(b.matches)) return res.status(400).json({ error:"invalid builder" });
    await saveLiveBuilder("battleground", b);

    // auto-create TOTAL ROUNDS BANDS draft from match count
    const m = Array.isArray(b.matches) ? b.matches.length : 0;
    if (m > 0){
      upsertDraft(buildTotalRoundsBandsDraft(m));
    }
    res.json({ success:true, autoDraft: m>0 });
  }catch(e){
    console.error("[BG] publish failed", e);
    res.status(500).json({ error:"failed" });
  }
});

// Bonus Hunt live/publish
app.get("/api/bonus-hunt/live", async (req,res)=>{
  try{ const b = await getLiveBuilder("bonus"); res.json({ builder: b || null }); }
  catch(e){ console.error("[BH] live get failed", e); res.status(500).json({ error:"failed" }); }
});
app.post("/api/bonus-hunt/builder", verifyAdminToken, async (req,res)=>{
  try{
    const raw = (req.body && typeof req.body==='object') ? req.body : null;
    const b = raw?.builder ?? raw; // expect { title, games:[], results:[], ... }
    if (!b || !Array.isArray(b.games)) return res.status(400).json({ error:"invalid builder" });
    await saveLiveBuilder("bonus", b);
    res.json({ success:true });
  }catch(e){
    console.error("[BH] publish failed", e);
    res.status(500).json({ error:"failed" });
  }
});

// Unified markets availability ping
app.get("/api/markets/unified", async (req, res) => {
  const bg = await getLiveBuilder("battleground");
  const bh = await getLiveBuilder("bonus");
  res.json({
    battleground: !!(bg && Array.isArray(bg.matches) && bg.matches.length),
    bonusHunt: !!(bh && Array.isArray(bh.games) && bh.games.length),
    meta: { ts: Date.now() }
  });
});

/* =========================== Bets Admin ============================ */

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
  memory.betsDrafts = memory.betsDrafts || [];
  memory.betsPublished = memory.betsPublished || [];
  const src = status === "published" ? memory.betsPublished : memory.betsDrafts;
  let items = [...src];
  if (kind) items = items.filter(x => String(x.kind||"").toLowerCase()===kind);
  res.json({ ok:true, items });
});

app.post("/api/admin/bets/publish", verifyAdminToken, (req,res)=>{
  const { id, all=false, kind="" } = req.body || {};
  memory.betsDrafts = memory.betsDrafts || [];
  memory.betsPublished = memory.betsPublished || [];

  if (all){
    const k = String(kind||"").toLowerCase();
    const moving = k ? memory.betsDrafts.filter(x => String(x.kind||"").toLowerCase()===k) : [...memory.betsDrafts];
    moving.forEach(evt => {
      memory.betsPublished = [evt, ...memory.betsPublished.filter(x => (x.eventId||x.id)!==(evt.eventId||evt.id))];
    });
    memory.betsDrafts = memory.betsDrafts.filter(x => !moving.includes(x));
    scheduleSave?.();
    return res.json({ ok:true, published: moving.length });
  } else {
    const i = memory.betsDrafts.findIndex(x => (x.eventId||x.id)===id);
    if (i<0) return res.status(404).json({ ok:false, error:"not found" });
    const evt = memory.betsDrafts[i];
    memory.betsDrafts.splice(i,1);
    memory.betsPublished = [evt, ...memory.betsPublished.filter(x => (x.eventId||x.id)!==(evt.eventId||evt.id))];
    scheduleSave?.();
    return res.json({ ok:true, id: (evt.eventId||evt.id) });
  }
});

// Public read for live bets
app.get("/api/bets/live", (req,res)=>{
  const kind = String(req.query.kind || "").toLowerCase();
  memory.betsPublished = memory.betsPublished || [];
  let items = [...memory.betsPublished];
  if (kind) items = items.filter(x => String(x.kind||"").toLowerCase()===kind);
  res.json({ ok:true, items, ts: Date.now() });
});

// Legacy alias
app.get("/api/bets/published", (req, res) => {
  const kind = String(req.query.kind || "").toLowerCase();
  memory.betsPublished = memory.betsPublished || [];
  let items = [...memory.betsPublished];
  if (kind) items = items.filter(x => String(x.kind || "").toLowerCase() === kind);
  res.json({ ok: true, items, ts: Date.now() });
});

/* =================================================================== */
/* =================== 404 / Error + Start / DB Boot ================= */
/* =================================================================== */

// 404
app.use((req, res) => res.status(404).send("Not found."));

// Error
app.use((err, req, res, next) => {
  console.error("[ERROR]", err?.stack || err);
  if (req.path && req.path.startsWith("/api")) return res.status(500).json({ error: "Server error" });
  res.status(500).send("Server error");
});

// Start server
app.listen(PORT, HOST, () => {
  console.log(`[Server] http://${HOST}:${PORT} (${NODE_ENV}) PUBLIC_DIR=${PUBLIC_DIR}`);
  console.log(`[Server] HOME_INDEX=${HOME_INDEX} hasHome=${HAS_HOME}`);
  console.log(`[Server] ADMIN_LOGIN_FILE=${ADMIN_LOGIN_FILE || "(none)"} | ADMIN_HUB_FILE=${ADMIN_HUB_FILE || "(none)"}`);
});

// DB + persistence boot (Mongo → file → memory)
(async () => {
  // Decide storage mode and prep file persistence early (helpers came earlier)
  const fileOk = typeof ensureWritableStatePath === "function" ? ensureWritableStatePath() : false;

  if (!MONGO_URI) {
    if (!ALLOW_MEMORY_FALLBACK) console.warn("[DB] No MONGO_URI; memory mode disabled.");
    else console.warn("[DB] No MONGO_URI; using FILE PERSIST (if available) or MEMORY.");
    if (typeof STATE_PERSIST !== "undefined" && STATE_PERSIST && fileOk && typeof loadStateIfPresent === "function") {
      globalThis.storageMode = "file";
      loadStateIfPresent();
      scheduleSave?.();
    } else {
      globalThis.storageMode = "memory";
    }
    return;
  }

  try {
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 8000 });
    await client.connect();
    globalThis.__db = client.db(MONGO_DB);
    globalThis.__dbReady = true;
    globalThis.storageMode = "mongo";
    console.log(`[DB] Connected to MongoDB: ${MONGO_DB}`);

    // optional: ensure indexes used by promos/leaderboards (helpers defined earlier)
    if (typeof ensurePromoIndexes === "function") await ensurePromoIndexes(globalThis.__db);
    if (typeof ensureLeaderboardIndexes === "function") await ensureLeaderboardIndexes(globalThis.__db);
  } catch (err) {
    console.error("[DB] Mongo connection failed:", err?.message || err);
    if (!ALLOW_MEMORY_FALLBACK) { console.error("[DB] ALLOW_MEMORY_FALLBACK=false — exiting"); process.exit(1); }
    console.warn("[DB] Continuing without Mongo.");
    if (typeof STATE_PERSIST !== "undefined" && STATE_PERSIST && fileOk && typeof loadStateIfPresent === "function") {
      globalThis.storageMode = "file";
      loadStateIfPresent();
      scheduleSave?.();
    } else {
      globalThis.storageMode = "memory";
    }
  }
})();
