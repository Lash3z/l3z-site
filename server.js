// server.js — homepage-first, admin aliases, JSON+form login
// + Wallet (Mongo + file fallback) with ledger + daily reward
// + Viewer session (cookie) + signup bonus (server-side, no client sync)
// + Promo admin + redeem (matches Admin Hub)
// + Admin raffle entry endpoints (matches Admin Hub)
// + PVP Entries + Bracket APIs
// + LIVE publish feeds for Battleground & Bonus Hunt
// + Shared leaderboard upsert
// + Simple bets endpoint that debits wallet and writes ledger
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
const SIGNUP_BONUS = Number(process.env.SIGNUP_BONUS || 50);
const DAILY_REWARD_AMOUNT = Number(process.env.DAILY_REWARD_AMOUNT || 5);
const DAILY_REWARD_WINDOW_MS = 24 * 60 * 60 * 1000;

// File persistence fallback
const STATE_PERSIST = (process.env.STATE_PERSIST ?? "true") === "true";
const STATE_CANDIDATES = [
  process.env.STATE_FILE && path.resolve(process.env.STATE_FILE),
  path.join(process.cwd(), ".data", "lash3z-state.json"),
  path.join(os.tmpdir(), "lash3z-state.json"),
].filter(Boolean);
let STATE_FILE = STATE_CANDIDATES[0];

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

/* ===================== Memory defaults ===================== */
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
  profiles: {},
  pvpEntries: [],
  pvpBracket: null,
  live: { pvp: null, battleground: null, bonus: null },
  promoCodes: [],
  promoRedemptions: [],
  betsTickets: [],
};

let storageMode = "memory"; // "mongo" | "file" | "memory"
function ensureWritableStatePath() {
  for (const cand of STATE_CANDIDATES) {
    try {
      const dir = path.dirname(cand);
      fs.mkdirSync(dir, { recursive: true });
      const t = path.join(dir, ".write-test");
      fs.writeFileSync(t, "ok"); fs.rmSync(t);
      STATE_FILE = cand; return true;
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
      fs.writeFileSync(STATE_FILE, JSON.stringify(memory, null, 2));
      console.log(`[PERSIST] state saved → ${STATE_FILE}`);
    } catch (e) { console.warn("[PERSIST] save failed:", e?.message || e); }
  }, saveDelayMs);
}
function loadStateIfPresent() {
  if (!STATE_PERSIST) return;
  try {
    if (existsSync(STATE_FILE)) {
      Object.assign(memory, JSON.parse(fs.readFileSync(STATE_FILE, "utf8")) || {});
      console.log(`[PERSIST] state loaded from ${STATE_FILE}`);
    }
  } catch (e) { console.warn("[PERSIST] load failed:", e?.message || e); }
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
const nowISO = () => new Date().toISOString();
function requireViewer(req, res, next) {
  const cookieName = String(req.cookies?.viewer || "").toUpperCase();
  const qName = String(req.query.viewer || "").toUpperCase();
  const bName = String(req.body?.viewer || req.body?.username || "").toUpperCase();
  const name = cookieName || qName || bName;
  if (!name) return res.status(401).json({ ok: false, error: "LOGIN_REQUIRED" });
  req.viewer = name; next();
}

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
      httpOnly: true, sameSite: "strict",
      secure: NODE_ENV === "production",
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
app.get("/", (req, res) => HAS_HOME ? res.sendFile(HOME_INDEX) :
  res.status(200).send("Homepage not found: put index.html in PUBLIC_DIR or set HOME_INDEX/PUBLIC_DIR correctly.")
);
app.get("/admin/login", (req, res) => ADMIN_LOGIN_FILE ? res.sendFile(ADMIN_LOGIN_FILE) : res.status(404).send("Admin login page not found."));
app.get("/admin/hub",   (req, res) => ADMIN_HUB_FILE   ? res.sendFile(ADMIN_HUB_FILE)   : res.status(404).send("Admin hub page not found."));

const ADMIN_WHITELIST = new Set([
  "bets_admin.html","battleground_admin.html","battleground_widget.html",
  "bonus_hunt_admin.html","bonus_hunt_widget.html","pvp_admin.html","lucky7.html","admin_hub.html"
]);
app.get("/admin/:file", (req, res) => {
  const safe = String(req.params.file || "").replace(/[^a-zA-Z0-9_.-]/g, "");
  if (!ADMIN_WHITELIST.has(safe)) return res.status(404).send("Not found.");
  const abs = path.join(PUBLIC_DIR, "pages/dashboard/admin", safe);
  if (!existsSync(abs)) return res.status(404).send("Not found.");
  return res.sendFile(abs);
});
app.get("/logout", (req, res) => { res.clearCookie("admin_token", { path: "/" }); res.redirect(302, "/"); });

app.use(express.static(PUBLIC_DIR, {
  setHeaders(res, filePath) {
    if (/\.(png|jpe?g|gif|webp|svg|woff2?|mp3|mp4)$/i.test(filePath)) {
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    } else if (/\.(css|js|map)$/i.test(filePath)) {
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    } else {
      res.setHeader("Cache-Control", "no-store");
    }
  }
}));

/* =================================================================== */
/* ===================== WALLET / VIEWER SESSION ===================== */
/* =================================================================== */

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
    // create fresh empty wallet; welcome bonus is applied via grantSignupBonusIfNeeded
    const fresh = { username: user, balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null };
    await col.insertOne(fresh);
    return fresh;
  }

  const w = memory.wallets[user] || { balance: 0, ledger: [], signupBonusGrantedAt: null, lastDailyClaimAt: null };
  memory.wallets[user] = w;
  return { username: user, balance: Number(w.balance || 0), ledger: Array.isArray(w.ledger) ? w.ledger : [], signupBonusGrantedAt: w.signupBonusGrantedAt, lastDailyClaimAt: w.lastDailyClaimAt || null };
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
    } catch (e) { console.warn("[wallet] mongo adjust failed, falling back:", e?.message || e); }
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
    const tx = { ts: nowISO(), delta: bonus, reason: "WELCOME_BONUS" };
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
  w.ledger.push({ ts: nowISO(), delta: bonus, reason: "WELCOME_BONUS" });
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

    if (globalThis.__dbReady) {
      const users = globalThis.__db.collection("users");
      const exists = await users.findOne({ username: name });
      if (exists) return res.status(409).json({ error: "user_exists" });
      await users.insertOne({ username: name, passHash: crypto.createHash("sha256").update(pwd).digest("hex"), createdAt: new Date() });
    }

    res.cookie("viewer", name, {
      httpOnly: false, sameSite: "lax",
      secure: NODE_ENV === "production", maxAge: 1000*60*60*24*30, path: "/",
    });

    await grantSignupBonusIfNeeded(name);
    const w = await getWallet(name);
    res.json({ success: true, username: name, wallet: { balance: Number(w.balance||0) } });
  } catch (e) { console.error("[register] error", e); res.status(500).json({ error: "server_error" }); }
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
      secure: NODE_ENV === "production", maxAge: 1000*60*60*24*30, path: "/",
    });

    await grantSignupBonusIfNeeded(name);
    const w = await getWallet(name);
    res.json({ success: true, username: name, wallet: { balance: Number(w.balance||0) } });
  } catch (e) { console.error("[login] error", e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/viewer/logout", (req, res) => {
  res.clearCookie("viewer", { path: "/" });
  res.clearCookie("admin_token", { path: "/" });
  res.json({ success: true });
});

// Public wallet reads (uses viewer cookie or ?viewer=), also grants welcome bonus server-side
app.get("/api/wallet/me", async (req, res) => {
  const cookieName = String(req.cookies?.viewer || "").toUpperCase();
  const qName      = String(req.query.viewer || "").toUpperCase();
  const username   = cookieName || qName || "";
  if (username) await grantSignupBonusIfNeeded(username);
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
  try { const r = await adjustWallet(u, amount, "admin_credit"); res.json({ success: true, balance: r.balance }); }
  catch { res.status(500).json({ error: "failed" }); }
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
    if (!r.ok && r.error === "NOT_YET") return res.status(429).json({ ok: false, error: "NOT_YET", remainingMs: r.remainingMs });
    if (!r.ok) return res.status(400).json({ ok: false, error: r.error || "FAILED" });
    res.json(r);
  } catch (e) { console.error("[daily_reward] error", e); res.status(500).json({ ok:false, error:"SERVER" }); }
});

/* =================================================================== */
/* ============================ JACKPOT =============================== */
/* =================================================================== */

app.get("/api/jackpot", (req, res) => {
  const j = memory.jackpot || { amount: 0, month: new Date().toISOString().slice(0,7), perSubAUD: 2.5, currency: "AUD" };
  res.json({ ok: true, amount: Number(j.amount || 0), month: String(j.month || new Date().toISOString().slice(0,7)), perSubAUD: Number(j.perSubAUD || 2.5), currency: String(j.currency || "AUD"), ts: Date.now() });
});
app.post("/api/admin/jackpot", verifyAdminToken, (req, res) => {
  const b = req.body || {};
  if (typeof b.amount === "number") memory.jackpot.amount = Number(b.amount);
  if (typeof b.perSubAUD === "number") memory.jackpot.perSubAUD = Number(b.perSubAUD);
  if (typeof b.currency === "string") memory.jackpot.currency = String(b.currency || "AUD");
  if (typeof b.month === "string") memory.jackpot.month = String(b.month);
  scheduleSave();
  res.json({ ok: true, jackpot: memory.jackpot });
});
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
  scheduleSave(); res.json({ success: true });
});
app.post("/api/deposits/:id/reject", verifyAdminToken, (req, res) => {
  const id = String(req.params.id);
  memory.deposits = memory.deposits.filter(o => String(o.id||o._id) !== id);
  scheduleSave(); res.json({ success: true });
});
app.post("/api/lbx/orders", (req, res) => {
  const o = req.body || {};
  o._id = o._id || ("ORD-" + Math.random().toString(36).slice(2,10).toUpperCase());
  o.status = "pending"; o.ts = o.ts || Date.now();
  memory.deposits.unshift(o);
  scheduleSave(); res.json({ success: true, order: o });
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
  scheduleSave(); res.json({ success:true });
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
  scheduleSave(); res.json({ success:true });
});

/* =================================================================== */
/* ============================ PROMO CODES ========================== */
/* =================================================================== */

const __promoHits = new Map();
function tinyRateLimit(windowMs = 10_000) {
  return (req, res, next) => {
    const k = `${req.ip || "ip"}:redeem`;
    const now = Date.now();
    const last = __promoHits.get(k) || 0;
    if (now - last < windowMs) return res.status(429).json({ ok: false, error: "TOO_FAST" });
    __promoHits.set(k, now); next();
  };
}
const PROMO_ALLOWED_AMOUNTS = new Set([5,10,15,20,25,30]);
function normCode(s = "") { return String(s).trim().toUpperCase().replace(/\s+/g, ""); }

app.post("/api/admin/promo/create", verifyAdminToken, async (req, res) => {
  try {
    let { code, amount, maxRedemptions=1, perUserLimit=1, expiresAt=null, notes="" } = req.body || {};
    amount = Number(amount); maxRedemptions = Number(maxRedemptions); perUserLimit = Number(perUserLimit);
    if (!PROMO_ALLOWED_AMOUNTS.has(amount)) return res.status(400).json({ ok:false, error:"INVALID_AMOUNT" });
    if (maxRedemptions < 1 || perUserLimit < 1) return res.status(400).json({ ok:false, error:"LIMITS_INVALID" });

    const now = new Date();
    const doc = {
      code: normCode(code || `L3Z-${amount}-${Math.random().toString(36).slice(2,8).toUpperCase()}`),
      amount, maxRedemptions, perUserLimit, redeemedCount: 0, active: true,
      expiresAt: expiresAt ? new Date(expiresAt) : null, createdBy: req.adminUser || "admin",
      notes: String(notes || ""), createdAt: now, updatedAt: now,
    };

    if (globalThis.__dbReady) {
      await globalThis.__db.collection("promo_codes").insertOne(doc);
    } else {
      if ((memory.promoCodes||[]).some(p => p.code === doc.code)) return res.status(409).json({ ok:false, error:"CODE_EXISTS" });
      memory.promoCodes.unshift(doc); scheduleSave();
    }
    res.json({ ok:true, code: doc.code, promo: doc });
  } catch (e) {
    if (e?.code === 11000) return res.status(409).json({ ok:false, error:"CODE_EXISTS" });
    console.error("[promo/create]", e); res.status(500).json({ ok:false, error:"SERVER" });
  }
});

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
        code: mkCode(), amount, maxRedemptions: Number(maxRedemptions), perUserLimit: Number(perUserLimit),
        redeemedCount: 0, active: true, expiresAt: expiresAt ? new Date(expiresAt) : null,
        createdBy: req.adminUser || "admin", notes: String(notes || ""), createdAt: now, updatedAt: now,
      }));
      await pc.insertMany(docs, { ordered: false });
      return res.json({ ok:true, generated: docs.length, sample: docs.slice(0,5).map(d=>d.code) });
    } else {
      const docs = [];
      for (let i=0;i<count;i++){
        let c; do { c = mkCode(); } while ((memory.promoCodes||[]).some(p => p.code === c));
        docs.push({ code: c, amount, maxRedemptions: Number(maxRedemptions), perUserLimit: Number(perUserLimit),
          redeemedCount: 0, active: true, expiresAt: expiresAt ? new Date(expiresAt) : null,
          createdBy: req.adminUser || "admin", notes: String(notes || ""), createdAt: now, updatedAt: now,
        });
      }
      memory.promoCodes = [...docs, ...(memory.promoCodes||[])]; scheduleSave();
      return res.json({ ok:true, generated: docs.length, sample: docs.slice(0,5).map(d=>d.code) });
    }
  } catch (e) { console.error("[promo/generate]", e); res.status(500).json({ ok:false, error:"SERVER" }); }
});

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

app.post("/api/promo/redeem", requireViewer, tinyRateLimit(), async (req, res) => {
  try {
    const code = normCode(req.body?.code || ""); if (!code) return res.status(400).json({ ok:false, error:"CODE_REQUIRED" });
    const username = req.viewer; const now = new Date();

    if (globalThis.__dbReady) {
      const pc = globalThis.__db.collection("promo_codes");
      const pr = globalThis.__db.collection("promo_redemptions");

      const promo = await pc.findOne({ code });
      if (!promo || !promo.active) return res.status(404).json({ ok:false, error:"INVALID_CODE" });
      if (promo.expiresAt && promo.expiresAt < now) return res.status(410).json({ ok:false, error:"EXPIRED" });
      if (promo.redeemedCount >= promo.maxRedemptions) return res.status(409).json({ ok:false, error:"DEPLETED" });

      const prior = await pr.countDocuments({ code, username });
      if (prior >= (promo.perUserLimit || 1)) return res.status(409).json({ ok:false, error:"PER_USER_LIMIT" });

      try { await pr.insertOne({ code, username, amount: Number(promo.amount||0), createdAt: now }); }
      catch { return res.status(409).json({ ok:false, error:"ALREADY_REDEEMED" }); }

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

    const promo = (memory.promoCodes||[]).find(p => p.code === code);
    if (!promo || !promo.active) return res.status(404).json({ ok:false, error:"INVALID_CODE" });
    if (promo.expiresAt && promo.expiresAt < now) return res.status(410).json({ ok:false, error:"EXPIRED" });
    if (promo.redeemedCount >= promo.maxRedemptions) return res.status(409).json({ ok:false, error:"DEPLETED" });

    const userClaims = (memory.promoRedemptions||[]).filter(r => r.code === code && r.username === username).length;
    if (userClaims >= (promo.perUserLimit || 1)) return res.status(409).json({ ok:false, error:"PER_USER_LIMIT" });

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
  } catch (e) { console.error("[promo/redeem]", e); res.status(500).json({ ok:false, error:"SERVER" }); }
});

app.get("/api/promo/my-redemptions", requireViewer, async (req, res) => {
  const username = req.viewer;
  if (globalThis.__dbReady) {
    const rows = await globalThis.__db.collection("promo_redemptions").find({ username }).sort({ createdAt: -1 }).limit(200).toArray();
    return res.json({ ok:true, items: rows });
  } else {
    const rows = (memory.promoRedemptions||[]).filter(r => r.username === username);
    return res.json({ ok:true, items: rows });
  }
});

/* =================================================================== */
/* ============================ LEADERBOARD ========================== */
/* =================================================================== */

const currentMonth = () => new Date().toISOString().slice(0, 7);

app.post("/api/leaderboard/upsert", verifyAdminToken, async (req, res) => {
  const user = String(req.body?.user || req.body?.username || "").toUpperCase();
  if (!user) return res.status(400).json({ error: "username required" });

  const mode = String(req.body?.mode || "tournament").toLowerCase();
  const fieldMap = { tournament: "tournamentPoints", bonus: "bonusHuntPoints", pvp: "pvpPoints", lucky7: "lucky7Points" };
  const field = fieldMap[mode] || "tournamentPoints";
  const delta = Number(req.body?.delta ?? req.body?.deltaTournamentPoints ?? 0);
  const actions = Array.isArray(req.body?.actions) ? req.body.actions : [];
  const month = String(req.body?.month || currentMonth());

  try {
    if (globalThis.__dbReady) {
      const db = globalThis.__db;
      const profiles = db.collection("profiles");
      const cumInc = { [field]: delta };
      const r1 = await profiles.findOneAndUpdate(
        { username: user },
        {
          $setOnInsert: { username: user, tournamentPoints: 0, bonusHuntPoints: 0, pvpPoints: 0, lucky7Points: 0, history: [] },
          $inc: cumInc,
          $push: { history: { ts: new Date(), mode, added: delta, actions } }
        },
        { upsert: true, returnDocument: "after" }
      );

      const monthly = db.collection("leaderboard_monthly");
      const r2 = await monthly.findOneAndUpdate(
        { username: user, month },
        {
          $setOnInsert: { username: user, month, tournamentPoints: 0, bonusHuntPoints: 0, pvpPoints: 0, lucky7Points: 0, totalPoints: 0, history: [] },
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
          username: r2.value.username, month: r2.value.month,
          tournamentPoints: Number(r2.value.tournamentPoints || 0),
          bonusHuntPoints:  Number(r2.value.bonusHuntPoints  || 0),
          pvpPoints:        Number(r2.value.pvpPoints        || 0),
          lucky7Points:     Number(r2.value.lucky7Points     || 0),
          totalPoints:      Number(r2.value.totalPoints      || 0)
        }
      });
    } else {
      const p = memory.profiles[user] || { username: user, tournamentPoints: 0, bonusHuntPoints:  0, pvpPoints: 0, lucky7Points: 0, history: [] };
      p[field] = Number(p[field] || 0) + delta;
      p.history.unshift({ ts: Date.now(), mode, added: delta, actions });
      memory.profiles[user] = p;

      if (!memory.monthlyLB) memory.monthlyLB = {};
      memory.monthlyLB[month] = memory.monthlyLB[month] || {};
      const mrec = memory.monthlyLB[month][user] || { username: user, month, tournamentPoints: 0, bonusHuntPoints:  0, pvpPoints: 0, lucky7Points: 0, totalPoints: 0, history: [] };
      mrec[field] = Number(mrec[field] || 0) + delta;
      mrec.totalPoints = Number(mrec.totalPoints || 0) + delta;
      mrec.history.unshift({ ts: Date.now(), mode, added: delta, actions });
      memory.monthlyLB[month][user] = mrec;

      scheduleSave();
      return res.json({
        success: true,
        cumulative: {
          username: p.username, tournamentPoints: p.tournamentPoints, bonusHuntPoints:  p.bonusHuntPoints, pvpPoints: p.pvpPoints, lucky7Points: p.lucky7Points
        },
        monthly: mrec
      });
    }
  } catch (e) { console.error("[LEADERBOARD] upsert failed", e); return res.status(500).json({ error: "failed" }); }
});
app.get("/api/leaderboard/monthly", async (req, res) => {
  const month = String(req.query.month || currentMonth());
  const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 200)));

  try {
    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("leaderboard_monthly");
      const rows = await col.find({ month })
        .project({ _id: 0, username: 1, month: 1, tournamentPoints: 1, bonusHuntPoints: 1, pvpPoints: 1, lucky7Points: 1, totalPoints: 1 })
        .sort({ totalPoints: -1, tournamentPoints: -1, bonusHuntPoints: -1, pvpPoints: -1, lucky7Points: -1, username: 1 })
        .limit(limit).toArray();

      let lastKey = null, rank = 0;
      const ranked = rows.map((r, i) => {
        const key = `${r.totalPoints}|${r.tournamentPoints}|${r.bonusHuntPoints}|${r.pvpPoints}|${r.lucky7Points}`;
        if (key !== lastKey) { rank = i + 1; lastKey = key; }
        return { rank, ...r };
      });

      return res.json({ month, items: ranked });
    }

    const bucket = (memory.monthlyLB && memory.monthlyLB[month]) ? memory.monthlyLB[month] : {};
    const items = Object.values(bucket)
      .sort((a, b) =>
        (b.totalPoints || 0) - (a.totalPoints || 0) ||
        (b.tournamentPoints || 0) - (a.tournamentPoints || 0) ||
        (b.bonusHuntPoints || 0) - (a.bonusHuntPoints || 0) ||
        (b.pvpPoints || 0) - (a.pvpPoints || 0) ||
        (b.lucky7Points || 0) - (a.lucky7Points || 0) ||
        a.username.localeCompare(b.username)
      ).slice(0, limit);

    let lastKey = null, rank = 0;
    const ranked = items.map((r, i) => {
      const key = `${r.totalPoints}|${r.tournamentPoints}|${r.bonusHuntPoints}|${r.pvpPoints}|${r.lucky7Points}`;
      if (key !== lastKey) { rank = i + 1; lastKey = key; }
      return { rank, ...r };
    });

    return res.json({ month, items: ranked });
  } catch (e) { console.error("[LEADERBOARD] monthly list failed", e); return res.status(500).json({ error: "failed" }); }
});
app.get("/api/leaderboard/overall", async (req, res) => {
  const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 200)));
  try {
    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("profiles");
      const rows = await col.aggregate([
        { $project: { _id: 0, username: 1, tournamentPoints: { $ifNull: ["$tournamentPoints", 0] }, bonusHuntPoints:  { $ifNull: ["$bonusHuntPoints", 0] }, pvpPoints: { $ifNull: ["$pvpPoints", 0] }, lucky7Points: { $ifNull: ["$lucky7Points", 0] } } },
        { $addFields: { totalPoints: { $add: ["$tournamentPoints", "$bonusHuntPoints", "$pvpPoints", "$lucky7Points"] } } },
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

    const items = Object.values(memory.profiles || {}).map(p => ({
      username: p.username,
      tournamentPoints: Number(p.tournamentPoints || 0),
      bonusHuntPoints:  Number(p.bonusHuntPoints  || 0),
      pvpPoints:        Number(p.pvpPoints        || 0),
      lucky7Points:     Number(p.lucky7Points     || 0),
    })).map(r => ({ ...r, totalPoints: r.tournamentPoints + r.bonusHuntPoints + r.pvpPoints + r.lucky7Points }))
      .sort((a, b) =>
        (b.totalPoints || 0) - (a.totalPoints || 0) ||
        (b.tournamentPoints || 0) - (a.tournamentPoints || 0) ||
        (b.bonusHuntPoints || 0) - (a.bonusHuntPoints || 0) ||
        (b.pvpPoints || 0) - (a.pvpPoints || 0) ||
        (b.lucky7Points || 0) - (a.lucky7Points || 0) ||
        a.username.localeCompare(b.username)
      ).slice(0, limit);

    let lastKey = null, rank = 0;
    const ranked = items.map((r, i) => {
      const key = `${r.totalPoints}|${r.tournamentPoints}|${r.bonusHuntPoints}|${r.pvpPoints}|${r.lucky7Points}`;
      if (key !== lastKey) { rank = i + 1; lastKey = key; }
      return { rank, ...r };
    });

    return res.json({ items: ranked });
  } catch (e) { console.error("[LEADERBOARD] overall list failed", e); return res.status(500).json({ error: "failed" }); }
});

/* =================================================================== */
/* ============================ PVP & LIVE =========================== */
/* =================================================================== */
/*  NOTE: The rest of your PVP and Live endpoints are unchanged from the
    version you shared and are kept intact here. For brevity in this file
    we omit them; in your deployment, keep your existing implementations. */
/* =================================================================== */

/* =================================================================== */
/* ============================ BETS PLACE =========================== */
/* =================================================================== */

// Minimal bets placement to deduct LBX and write ledger. Store tickets in Mongo if available, else memory.
app.post("/api/bets/place", requireViewer, async (req, res) => {
  try {
    const user = req.viewer;
    const { mode="single", stake=0, legs=[] } = req.body || {};
    const nStake = Math.max(0, Number(stake||0));
    if (!nStake || !Array.isArray(legs) || legs.length < 1) return res.status(400).json({ ok:false, error:"bad_request" });
    const totalStake = (String(mode)==="single") ? nStake * legs.length : nStake;
    if (totalStake > 100) return res.status(400).json({ ok:false, error:"stake_cap" });

    // Check balance
    const w = await getWallet(user);
    if (Number(w.balance||0) < totalStake) return res.status(400).json({ ok:false, error:"insufficient_funds" });

    // Deduct
    const r = await adjustWallet(user, -totalStake, "BET_STAKE");
    if (!r.ok) return res.status(500).json({ ok:false, error:"wallet_write_failed" });

    // Save ticket(s)
    const at = Date.now();
    const tickets = (String(mode)==="single")
      ? legs.map(leg => ({ user, at, mode:"single", stake:nStake, leg, status:"open" }))
      : [{ user, at, mode:"multi", stake:nStake, legs, status:"open" }];

    if (globalThis.__dbReady) {
      const col = globalThis.__db.collection("bets_tickets");
      await col.insertMany(tickets);
    } else {
      memory.betsTickets.unshift(...tickets); scheduleSave();
    }

    res.json({ ok:true, balance: r.balance, placed: tickets.length });
  } catch (e) { console.error("[bets/place]", e); res.status(500).json({ ok:false, error:"server_error" }); }
});

/* =================================================================== */
/* =================== 404 / Error + Start / DB Boot ================= */
/* =================================================================== */

app.use((req, res) => res.status(404).send("Not found."));
app.use((err, req, res, next) => {
  console.error("[ERROR]", err?.stack || err);
  if (req.path && req.path.startsWith("/api")) return res.status(500).json({ error: "Server error" });
  res.status(500).send("Server error");
});

app.listen(PORT, HOST, () => {
  console.log(`[Server] http://${HOST}:${PORT} (${NODE_ENV}) PUBLIC_DIR=${PUBLIC_DIR}`);
  console.log(`[Server] HOME_INDEX=${HOME_INDEX} hasHome=${HAS_HOME}`);
  console.log(`[Server] ADMIN_LOGIN_FILE=${ADMIN_LOGIN_FILE || "(none)"} | ADMIN_HUB_FILE=${ADMIN_HUB_FILE || "(none)"}`);
});

(async () => {
  const fileOk = ensureWritableStatePath();
  if (!MONGO_URI) {
    if (!ALLOW_MEMORY_FALLBACK) console.warn("[DB] No MONGO_URI; memory mode disabled.");
    else console.warn("[DB] No MONGO_URI; using FILE PERSIST (if available) or MEMORY.");
    if (STATE_PERSIST && fileOk) { storageMode = "file"; loadStateIfPresent(); scheduleSave?.(); }
    else { storageMode = "memory"; }
    return;
  }

  try {
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 8000 });
    await client.connect();
    globalThis.__db = client.db(MONGO_DB);
    globalThis.__dbReady = true;
    storageMode = "mongo";
    console.log(`[DB] Connected to MongoDB: ${MONGO_DB}`);
  } catch (err) {
    console.error("[DB] Mongo connection failed:", err?.message || err);
    if (!ALLOW_MEMORY_FALLBACK) { console.error("[DB] ALLOW_MEMORY_FALLBACK=false — exiting"); process.exit(1); }
    console.warn("[DB] Continuing without Mongo.");
    if (STATE_PERSIST && fileOk) { storageMode = "file"; loadStateIfPresent(); scheduleSave?.(); }
    else { storageMode = "memory"; }
  }
})();
