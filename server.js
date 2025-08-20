// server.js — server-backed wallet + bets + promo + admin audit
// Mongo → file → memory fallback. NO localStorage balances anywhere.
//
// Features
// - Wallet APIs (with ledger), signup bonus (optional), daily reward
// - Viewer session (cookie-based)
// - Bets: place + list (deduct from wallet, store tickets)
// - Promo: init + routes (via ./promo.js)
// - Admin audit tracking + bulk promo expire
// - Static hosting + CORS + hardened cookies/headers
//
// ENV (examples)
// HOST=0.0.0.0
// PORT=3000
// NODE_ENV=production
// ADMIN_USER=lash3z
// ADMIN_PASS=***
// ADMIN_SECRET=***
// SECRET=***           # JWT secret (falls back to ADMIN_SECRET)
// MONGO_URI=mongodb+srv://...
// MONGO_DB=lash3z
// ALLOW_MEMORY_FALLBACK=true
// ALLOWED_ORIGINS=https://your-site.com,https://admin.your-site.com
// SIGNUP_BONUS=0
// DAILY_REWARD_AMOUNT=5
// STATE_PERSIST=true
// STATE_FILE=/app/.data/lash3z-state.json
// PUBLIC_DIR=/app/public
// HOME_INDEX=index.html

import fs from "fs";
import os from "os";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";

// Promo module
import { initPromo, promoRoutes } from "./promo.js";

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
const SIGNUP_BONUS = Number(process.env.SIGNUP_BONUS || 0); // 0 disables
const DAILY_REWARD_AMOUNT = Number(process.env.DAILY_REWARD_AMOUNT || 5);
const DAILY_REWARD_WINDOW_MS = 24 * 60 * 60 * 1000;

// File persistence fallback (so balances persist without DB)
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

/* ===================== In-memory state ===================== */
const memory = {
  wallets: {},    // { USER: { balance, ledger[], signupBonusGrantedAt, lastDailyClaimAt } }
  tickets: [],    // server-backed tickets when no DB
  audit: [],      // admin audit when no DB
  promoCodes: [], // promo stub if no DB (promo.js handles Mongo)
};

/* ===================== File persistence helpers ===================== */
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

/* ===================== Auth helpers ===================== */
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
  req.viewer = name;
  next();
}

/* ===================== Admin auth (JSON or form) ===================== */
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

/* ===================== Health / Static ===================== */
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
/* ========================= WALLET & LEDGER ========================= */
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

/* ===================== Viewer session ===================== */
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

/* ===================== Wallet public read ===================== */
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

/* ===================== Admin wallet ops ===================== */
function parseUserFromBody(b){ return U(b?.username || b?.user || b?.name || ""); }

app.post("/api/wallet/adjust", verifyAdminToken, async (req, res) => {
  const u = parseUserFromBody(req.body);
  const delta = Number(req.body?.delta || req.body?.amount || 0);
  const why = String(req.body?.reason || "admin_adjust");
  if (!u) return res.status(400).json({ error: "username required" });
  try {
    const r = await adjustWallet(u, delta, why);
    return r?.ok ? res.json({ success: true, balance: r.balance }) : res.status(500).json({ error: r.error || "failed" });
  } catch (e) {
    console.error("[/api/wallet/adjust] error:", e);
    res.status(500).json({ error: "server_error" });
  }
});
app.post("/api/wallet/credit", verifyAdminToken, async (req, res) => {
  const u = parseUserFromBody(req.body);
  const amount = Number(req.body?.amount || req.body?.delta || 0);
  if (!u) return res.status(400).json({ error: "username required" });
  try {
    const r = await adjustWallet(u, amount, "admin_credit");
    res.json({ success: true, balance: r.balance });
  } catch (e) {
    console.error("[/api/wallet/credit] error:", e);
    res.status(500).json({ error: "failed" });
  }
});
app.get("/api/wallet/balance", verifyAdminToken, async (req, res) => {
  const u = U(req.query.user || req.query.username || "");
  const w = await getWallet(u);
  res.json({ balance: Number(w.balance || 0) });
});

/* ===================== Daily reward ===================== */
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
/* =============================== BETS ============================== */
/* =================================================================== */
// Minimal server-backed tickets so the client doesn't use localStorage.
//
// Ticket shape:
// {
//   id, user, at, mode: 'single'|'multi',
//   stake, odds, legs: [ { section, marketId, type, selIdx?, selLabel?, guess?, odds } ]
// }
//
// POST /api/bets/place    (viewer cookie required)
// GET  /api/bets/me       (viewer cookie OR ?viewer=)
// GET  /api/admin/bets    (admin; optional ?user=)

const MAX_SINGLE_STAKE = 100; // Max per submission (match your UI)

function newId(prefix="TK") { return `${prefix}-${Math.random().toString(36).slice(2,10).toUpperCase()}`; }

async function storeTickets(tickets = []) {
  if (globalThis.__dbReady) {
    const col = globalThis.__db.collection("tickets");
    await col.insertMany(tickets);
    return true;
  }
  memory.tickets.push(...tickets);
  scheduleSave();
  return true;
}

async function fetchTicketsByUser(user) {
  const u = U(user);
  if (globalThis.__dbReady) {
    const col = globalThis.__db.collection("tickets");
    return await col.find({ user: u }).sort({ at: -1 }).limit(500).toArray();
  }
  return (memory.tickets || []).filter(t => t.user === u).sort((a,b)=>b.at-a.at).slice(0,500);
}

app.post("/api/bets/place", requireViewer, async (req, res) => {
  try {
    const USER = req.viewer;
    const body = req.body || {};
    const { slipMode, stake, legs } = body;

    const mode = (slipMode || body.mode || "single").toLowerCase() === "multi" ? "multi" : "single";
    const s = Math.floor(Number(stake || 0));
    if (!(s > 0)) return res.status(400).json({ ok:false, error:"bad_stake" });
    if (!Array.isArray(legs) || legs.length < 1) return res.status(400).json({ ok:false, error:"no_legs" });

    const legsNorm = legs.map(l => ({
      section: String(l.section||"").toLowerCase(),
      marketId: String(l.marketId||""),
      type: String(l.type||"selection"),
      selIdx: Number.isFinite(l.selIdx) ? Number(l.selIdx) : undefined,
      selLabel: l.selLabel ? String(l.selLabel) : undefined,
      guess: l.guess !== undefined ? l.guess : undefined,
      odds: Number(l.odds||1)
    }));

    // compute required total stake + combined odds
    const totalStake = mode === "single" ? s * legsNorm.length : s;
    if (totalStake > MAX_SINGLE_STAKE) return res.status(400).json({ ok:false, error:"stake_limit" });

    const w = await getWallet(USER);
    if (Number(w.balance || 0) < totalStake) return res.status(400).json({ ok:false, error:"insufficient_funds" });

    let tickets = [];
    if (mode === "single") {
      tickets = legsNorm.map(leg => ({
        id: newId("TK"),
        user: USER,
        at: Date.now(),
        mode: "single",
        stake: s,
        odds: Number(leg.odds || 1),
        leg
      }));
    } else {
      const prod = legsNorm.reduce((p,x)=> p * Number(x.odds || 1), 1);
      tickets = [{
        id: newId("TK"),
        user: USER,
        at: Date.now(),
        mode: "multi",
        stake: s,
        odds: Number(prod),
        legs: legsNorm
      }];
    }

    // Deduct from wallet (+ ledger)
    await adjustWallet(USER, -totalStake, "BET_STAKE");

    // Store tickets
    await storeTickets(tickets);

    res.json({ ok: true, tickets, balanceAfter: (await getWallet(USER)).balance });
  } catch (e) {
    console.error("[bets/place]", e);
    res.status(500).json({ ok:false, error:"server" });
  }
});

app.get("/api/bets/me", async (req, res) => {
  try {
    const cookieName = String(req.cookies?.viewer || "").toUpperCase();
    const qName      = String(req.query.viewer || "").toUpperCase();
    const user       = cookieName || qName || "";
    if (!user) return res.status(401).json({ ok:false, error:"LOGIN_REQUIRED" });

    const list = await fetchTicketsByUser(user);
    res.json({ ok:true, tickets: list });
  } catch (e) {
    console.error("[bets/me]", e);
    res.status(500).json({ ok:false, error:"server" });
  }
});

app.get("/api/admin/bets", verifyAdminToken, async (req, res) => {
  try {
    const u = U(req.query.user || req.query.username || "");
    if (!u) {
      // list latest across users (limited)
      if (globalThis.__dbReady) {
        const col = globalThis.__db.collection("tickets");
        const list = await col.find({}).sort({ at: -1 }).limit(200).toArray();
        return res.json({ ok:true, tickets: list });
      }
      return res.json({ ok:true, tickets: (memory.tickets||[]).slice(-200).reverse() });
    }
    const list = await fetchTicketsByUser(u);
    res.json({ ok:true, tickets: list });
  } catch (e) {
    console.error("[admin/bets]", e);
    res.status(500).json({ ok:false, error:"server" });
  }
});

/* =================================================================== */
/* ============================== PROMO ============================== */
/* =================================================================== */

function wirePromoOrStub(app) {
  if (globalThis.__dbReady && globalThis.__db) {
    initPromo(globalThis.__db).then(() => {
      promoRoutes(app, globalThis.__db);
      console.log("[Promo] indexes ensured + routes mounted.");
    }).catch(e => {
      console.error("[Promo] init error:", e?.message || e);
      app.post("/api/promo/redeem", (req,res)=> res.status(503).json({ ok:false, error:"promo_init_failed" }));
      app.get ("/api/promo/my",      (req,res)=> res.status(503).json({}));
      app.post("/api/promo/issue",   (req,res)=> res.status(503).json({ ok:false, error:"promo_init_failed" }));
      app.post("/api/promo/expire",  (req,res)=> res.status(503).json({ ok:false, error:"promo_init_failed" }));
    });
  } else {
    app.post("/api/promo/redeem", (req,res)=> res.status(503).json({ ok:false, error:"db_required" }));
    app.get ("/api/promo/my",      (req,res)=> res.status(503).json({}));
    app.post("/api/promo/issue",   (req,res)=> res.status(503).json({ ok:false, error:"db_required" }));
    app.post("/api/promo/expire",  (req,res)=> res.status(503).json({ ok:false, error:"db_required" }));
    console.log("[Promo] stubbed (no DB).");
  }
}

// Bulk expire-all active promo codes (for your "reset" button)
app.post("/api/admin/promo/expire-all", verifyAdminToken, async (req, res) => {
  try {
    if (globalThis.__dbReady) {
      const r = await globalThis.__db.collection("promo_codes").updateMany(
        { status: "active" },
        { $set: { status: "expired", expiredAt: new Date(), note: "bulk_expire" } }
      );
      return res.json({ ok:true, modified: r.modifiedCount });
    }
    // memory fallback
    let n = 0;
    memory.promoCodes = (memory.promoCodes||[]).map(p => {
      if (p.status === "active") { n++; return { ...p, status:"expired", expiredAt: new Date() }; }
      return p;
    });
    scheduleSave();
    res.json({ ok:true, modified: n });
  } catch (e) {
    console.error("[promo/expire-all]", e);
    res.status(500).json({ ok:false, error:"server" });
  }
});

/* =================================================================== */
/* ============================ ADMIN AUDIT ========================== */
/* =================================================================== */
// Admin HUD calls this to "track" actions (who did what).
// POST /api/admin/audit/track  body: { action, meta? }

app.post("/api/admin/audit/track", verifyAdminToken, async (req, res) => {
  try {
    const doc = {
      action: String(req.body?.action || "").toUpperCase(),
      meta: req.body?.meta ?? null,
      actor: String(req.adminUser || "admin"),
      ip: req.ip || null,
      ts: Date.now()
    };
    if (globalThis.__dbReady) {
      await globalThis.__db.collection("admin_audit").insertOne(doc);
    } else {
      memory.audit.push(doc);
      scheduleSave();
    }
    res.json({ ok:true });
  } catch (e) {
    console.error("[admin/audit/track]", e);
    res.status(500).json({ ok:false, error:"server" });
  }
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

// DB boot (Mongo → file → memory)
(async () => {
  const fileOk = ensureWritableStatePath();

  if (!MONGO_URI) {
    if (!ALLOW_MEMORY_FALLBACK) console.warn("[DB] No MONGO_URI; memory mode disabled.");
    else console.warn("[DB] No MONGO_URI; using FILE PERSIST (if available) or MEMORY.");
    if (STATE_PERSIST && fileOk) {
      storageMode = "file";
      loadStateIfPresent();
      scheduleSave?.();
    } else {
      storageMode = "memory";
    }
    wirePromoOrStub(app);
    return;
  }

  try {
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 8000 });
    await client.connect();
    globalThis.__db = client.db(MONGO_DB);
    globalThis.__dbReady = true;
    storageMode = "mongo";
    console.log(`[DB] Connected to MongoDB: ${MONGO_DB}`);

    await initPromo(globalThis.__db);
    promoRoutes(app, globalThis.__db);
    console.log("[Promo] indexes ensured + routes mounted.");
  } catch (err) {
    console.error("[DB] Mongo connection failed:", err?.message || err);
    if (!ALLOW_MEMORY_FALLBACK) { console.error("[DB] ALLOW_MEMORY_FALLBACK=false — exiting"); process.exit(1); }
    console.warn("[DB] Continuing without Mongo.");
    if (STATE_PERSIST && fileOk) {
      storageMode = "file";
      loadStateIfPresent();
      scheduleSave?.();
    } else {
      storageMode = "memory";
    }
    wirePromoOrStub(app);
  }
})();
