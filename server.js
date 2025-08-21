// server.js — ESM
// Lifetime + Monthly leaderboard (no reset of lifetime)
// Wallet persistence: MongoDB if available, else safe file-persist (auto-fallback to /tmp), else memory.
// Includes: Kick OAuth, promos, raffles, PVP, BG/Bonus live, bets drafts/publish.

import fs from "fs";
import os from "os";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import helmet from "helmet";
import compression from "compression";
import morgan from "morgan";
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

// State-persist fallback (for when Mongo is not available)
const STATE_PERSIST = (process.env.STATE_PERSIST ?? "true") === "true";
const STATE_CANDIDATES = [
  process.env.STATE_FILE && path.resolve(process.env.STATE_FILE),
  path.join(process.cwd(), ".data", "lash3z-state.json"),
  path.join(os.tmpdir(), "lash3z-state.json"),
].filter(Boolean);
let STATE_FILE = STATE_CANDIDATES[0];

/* ===== Kick OAuth ENV ===== */
const KICK_OAUTH_AUTHORIZE = "https://id.kick.com/oauth/authorize";
const KICK_OAUTH_TOKEN     = "https://id.kick.com/oauth/token";
const KICK_API_BASE        = "https://api.kick.com/public/v1";
const KICK_CLIENT_ID       = process.env.KICK_CLIENT_ID || "";
const KICK_CLIENT_SECRET   = process.env.KICK_CLIENT_SECRET || "";
const KICK_REDIRECT_URI    = process.env.KICK_REDIRECT_URI || "https://lash3z.com/auth/kick/callback";
const KICK_SCOPES          = (process.env.KICK_SCOPES || "user:read channel:read events:read").split(/\s+/).filter(Boolean);

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

/* ===================== Persistence (file fallback) ===================== */
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
      // eslint-disable-next-line no-console
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
      // shallow merge; keep schema defaults for new keys
      Object.assign(memory, parsed || {});
      // eslint-disable-next-line no-console
      console.log(`[PERSIST] state loaded from ${STATE_FILE}`);
    }
  } catch (e) {
    console.warn("[PERSIST] load failed:", e?.message || e);
  }
}

/* ===================== Memory (default values) ===================== */
const memory = {
  jackpot: { amount: 0, month: new Date().toISOString().slice(0,7), perSubAUD: 2.5 },
  rules: {
    lbx: { SUB_NEW: 10, SUB_RENEW: 5, SUB_GIFT_GIFTER_PER: 2, SUB_GIFT_RECIPIENT: 3 },
    caps: { eventLBXPerUserPerDay: 100 },
    jackpotPerSubAUD: 2.50, jackpotCurrency: "AUD", depositContributesJackpot: false
  },
  events: [],
  wallets: {},        // wallets in fallback mode (with ledger)
  users: new Map(),   // memory-only user store when Mongo missing
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
  flags: { pvpEntriesOpen: true },

  // Promo codes (memory fallback)
  promoCodes: [],
  promoRedemptions: [],

  // Monthly leaderboard buckets (memory fallback)
  monthlyLB: {},   // { "YYYY-MM": { USER: { ...points } } }

  // meta
  __version: 1
};

/* ===================== App ===================== */
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(compression());
app.use(morgan(NODE_ENV === "production" ? "tiny" : "dev"));

// security headers already covered mostly by helmet
app.use((req, res, next) => {
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
    storageMode,
    stateFile: storageMode === "file" ? STATE_FILE : null,
    adminBypass: DISABLE_ADMIN_AUTH,
    kick: {
      configured: !!(KICK_CLIENT_ID && KICK_CLIENT_SECRET && KICK_REDIRECT_URI),
      redirect: KICK_REDIRECT_URI
    }
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
/* ===================== WALLET / USER HELPERS ============================ */
/* ======================================================================== */

const U = (s) => String(s || "").trim().toUpperCase();
const nowISO = () => new Date().toISOString();
const hash = (pwd) => crypto.createHash("sha256").update(String(pwd)).digest("hex");

// Leaderboard helpers
const currentMonth = () => new Date().toISOString().slice(0, 7); // "YYYY-MM"

// ===== PROMO HELPERS =====
function normCode(s = "") {
  return String(s).trim().toUpperCase().replace(/\s+/g, "");
}
function requireViewer(req, res, next) {
  const cookieName = String(req.cookies?.viewer || "").toUpperCase();
  const qName = String(req.query.viewer || "").toUpperCase();
  const bName = String(req.body?.viewer || req.body?.username || "").toUpperCase();
  const name = cookieName || qName || bName;
  if (!name) return res.status(401).json({ ok: false, error: "LOGIN_REQUIRED" });
  req.viewer = name;
  next();
}
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
// ===== END PROMO HELPERS =====

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

  // file/memory
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

  // file/memory
  const w = memory.wallets[user] || { balance: 0, ledger: [], signupBonusGrantedAt: null };
  w.balance = Number(w.balance || 0) + amount;
  w.ledger.push({ ts: nowISO(), delta: amount, reason });
  memory.wallets[user] = w;
  scheduleSave();
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

  // file/memory
  const w = memory.wallets[user] || { balance: 0, ledger: [], signupBonusGrantedAt: null };
  if (w.signupBonusGrantedAt) return { ok: true, skipped: true, balance: Number(w.balance || 0) };
  w.balance = Number(w.balance || 0) + bonus;
  w.signupBonusGrantedAt = new Date();
  w.ledger.push({ ts: nowISO(), delta: bonus, reason: "signup_bonus" });
  memory.wallets[user] = w;
  scheduleSave();
  return { ok: true, balance: w.balance };
}

// simple users store for /register when Mongo exists; memory fallback
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
    scheduleSave();
  }
  return doc;
}

/* ===================== Wallet + Viewer APIs ===================== */
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

// ✅ public wallet read
app.get("/api/wallet/me", async (req, res) => {
  const cookieName = String(req.cookies?.viewer || "").toUpperCase();
  const qName      = String(req.query.viewer || "").toUpperCase();
  const username   = cookieName || qName || "";
  const w = await getWallet(username);
  res.json({ username, wallet: { balance: Number(w.balance || 0) } });
});

/* ===================== Viewer session (unified login) ===================== */
app.post("/api/viewer/register", async (req, res) => {
  try {
    const name = U(req.body?.username || req.body?.user || "");
    const pwd  = String(req.body?.password || "");
    if (!name || !pwd) return res.status(400).json({ error: "missing_credentials" });

    const exists = await userFind(name);
    if (exists) return res.status(409).json({ error: "user_exists" });

    const passHash = hash(pwd);
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

// Login
app.post("/api/viewer/login", async (req, res) => {
  try {
    const name = String(req.body?.username || req.body?.user || "").trim().toUpperCase();
    const pwd  = String(req.body?.password || "");

    if (!name) return res.status(400).json({ error: "username required" });

    const existing = await userFind(name);
    if (existing?.passHash) {
      const ok = existing.passHash === hash(pwd);
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

/* ===================== Kick OAuth Linking ===================== */
/** We persist PKCE verifier + state in a secure, httpOnly cookie to avoid
 *  'invalid_state' if the process restarts or a different instance handles
 *  the callback. */
const PKCE_COOKIE = "kick_pkce";

function b64url(buf) {
  return buf.toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function sign(data) {
  const h = crypto.createHmac("sha256", JWT_SECRET).update(data).digest("hex");
  return h.slice(0, 16); // short tag
}
function setPkceCookie(res, payload) {
  const raw = JSON.stringify(payload);
  const tag = sign(raw);
  res.cookie(PKCE_COOKIE, `${tag}.${b64url(Buffer.from(raw))}`, {
    httpOnly: true,
    sameSite: "lax",
    secure: NODE_ENV === "production",
    maxAge: 5 * 60 * 1000, // 5 minutes
    path: "/",
  });
}
function readPkceCookie(req) {
  const v = req.cookies?.[PKCE_COOKIE];
  if (!v) return null;
  const [tag, dataB64] = String(v).split(".");
  try {
    const raw = Buffer.from(dataB64, "base64").toString("utf8");
    if (sign(raw) !== tag) return null;
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    return obj;
  } catch { return null; }
}

/** Save Kick link for a viewer */
async function saveKickLink(username, profile /*, tokens */) {
  const u = U(username);
  if (!u) return;
  if (globalThis.__dbReady) {
    await globalThis.__db.collection("users").updateOne(
      { username: u },
      {
        $setOnInsert: { username: u, createdAt: new Date() },
        $set: {
          kick: {
            id: profile.id,
            username: profile.username,
            linkedAt: new Date()
          }
        }
      },
      { upsert: true }
    );
  } else {
    const existing = memory.users.get(u) || { username: u, createdAt: new Date() };
    existing.kick = { id: profile.id, username: profile.username, linkedAt: new Date() };
    memory.users.set(u, existing);
    scheduleSave();
  }
}

async function getKickLink(username) {
  const u = U(username);
  if (!u) return null;
  if (globalThis.__dbReady) {
    const doc = await globalThis.__db.collection("users").findOne({ username: u }, { projection: { kick: 1 } });
    return doc?.kick || null;
  }
  const doc = memory.users.get(u);
  return doc?.kick || null;
}

async function clearKickLink(username) {
  const u = U(username);
  if (!u) return;
  if (globalThis.__dbReady) {
    await globalThis.__db.collection("users").updateOne({ username: u }, { $unset: { kick: "" } });
  } else {
    const doc = memory.users.get(u);
    if (doc) delete doc.kick;
    scheduleSave();
  }
}

// Start OAuth (requires a logged-in viewer cookie)
app.get("/auth/kick", requireViewer, (req, res) => {
  if (!(KICK_CLIENT_ID && KICK_CLIENT_SECRET && KICK_REDIRECT_URI)) {
    return res.status(500).send("Kick OAuth not configured.");
  }
  const state = b64url(crypto.randomBytes(16));
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());

  // Persist to cookie (viewer + verifier + state + ts)
  setPkceCookie(res, { viewer: req.viewer, verifier, state, ts: Date.now() });

  const url = new URL(KICK_OAUTH_AUTHORIZE);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", KICK_CLIENT_ID);
  url.searchParams.set("redirect_uri", KICK_REDIRECT_URI);
  url.searchParams.set("scope", KICK_SCOPES.join(" "));
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");

  res.redirect(url.toString());
});

// OAuth callback
app.get("/auth/kick/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    if (error) return res.redirect(`/profile?kickError=${encodeURIComponent(error_description || error)}`);

    const stored = readPkceCookie(req);
    res.clearCookie(PKCE_COOKIE, { path: "/" });

    if (!stored || !stored.state || stored.state !== state) {
      return res.redirect(`/profile?kickError=invalid_state`);
    }
    if (!code) return res.redirect(`/profile?kickError=missing_code`);

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: KICK_REDIRECT_URI,
      code_verifier: stored.verifier,
      code
    });

    const tokRes = await fetch(KICK_OAUTH_TOKEN, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const tokens = await tokRes.json();
    if (!tokRes.ok || !tokens?.access_token) {
      return res.redirect(`/profile?kickError=token_exchange_failed`);
    }

    const meRes = await fetch(`${KICK_API_BASE}/users/me`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const profile = await meRes.json();
    if (!meRes.ok || !profile?.id) {
      return res.redirect(`/profile?kickError=user_fetch_failed`);
    }

    await saveKickLink(stored.viewer, profile /*, tokens*/);

    res.redirect(`/profile?kickLinked=1`);
  } catch (e) {
    console.error("[Kick OAuth] callback error:", e);
    res.redirect(`/profile?kickError=exception`);
  }
});

// Link status (for the current viewer)
app.get("/api/kick/status", requireViewer, async (req, res) => {
  const k = await getKickLink(req.viewer);
  res.json({ ok: true, linked: !!k, kick: k || null });
});

// Unlink
app.post("/api/kick/unlink", requireViewer, async (req, res) => {
  await clearKickLink(req.viewer);
  res.json({ ok: true });
});

/* ===================== Deposits / Orders ===================== */
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

/* ===================== JACKPOT — PUBLIC + ADMIN ===================== */
// Public read (fixes 404s for /api/jackpot)
app.get("/api/jackpot", (req, res) => {
  const j = memory.jackpot || {};
  const currency = (memory.rules && memory.rules.jackpotCurrency) || "AUD";
  res.json({
    ok: true,
    jackpot: {
      amount: Number(j.amount || 0),
      month: j.month || currentMonth(),
      perSubAUD: Number(j.perSubAUD || memory.rules?.jackpotPerSubAUD || 0),
      currency
    },
    ts: Date.now()
  });
});

// Admin: update absolute values
app.post("/api/admin/jackpot/update", verifyAdminToken, (req, res) => {
  const { amount, month, perSubAUD } = req.body || {};
  if (amount !== undefined) memory.jackpot.amount = Number(amount) || 0;
  if (month) memory.jackpot.month = String(month);
  if (perSubAUD !== undefined) memory.jackpot.perSubAUD = Number(perSubAUD) || 0;
  scheduleSave();
  res.json({ ok: true, jackpot: memory.jackpot });
});

// Admin: increment by delta (e.g. per sub)
app.post("/api/admin/jackpot/increment", verifyAdminToken, (req, res) => {
  const { delta = 0, count = 1 } = req.body || {};
  // Auto-roll current month bucket if needed
  const cm = currentMonth();
  if (memory.jackpot.month !== cm) {
    memory.jackpot.month = cm;
    memory.jackpot.amount = Number(memory.jackpot.amount || 0); // keep running unless you want reset
  }
  const inc = Number(delta) * Number(count || 1);
  memory.jackpot.amount = Number(memory.jackpot.amount || 0) + (Number.isFinite(inc) ? inc : 0);
  scheduleSave();
  res.json({ ok: true, jackpot: memory.jackpot });
});

/* ===================== Raffles / Giveaways (admin shims) ===================== */
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
  scheduleSave();
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
  scheduleSave();
  res.json({ success: true });
});

/* ===================== Leaderboard (monthly + lifetime) ===================== */
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
app.post("/api/admin/leaderboard/rebuild", verifyAdminToken, (req,res)=> res.json({ success:true }));

// Read: monthly leaderboard (auto "resets" by month bucket)
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
    const bucket = memory.monthlyLB[month] || {};
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

// Read: lifetime (overall) leaderboard
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

/* ===================== PVP (entries + toggle) ===================== */

// Public: check if entries are open
app.get("/api/pvp/entries/open", (req,res)=>{
  res.json({ open: !!memory.flags.pvpEntriesOpen });
});

// Admin: open/close entries
app.post("/api/admin/pvp/entries/open", verifyAdminToken, (req,res)=>{
  const open = !!req.body?.open;
  memory.flags.pvpEntriesOpen = open;
  scheduleSave();
  res.json({ success:true, open });
});

app.post("/api/pvp/entries", async (req, res) => {
  const username = String(req.body?.username || req.body?.user || "").trim().toUpperCase();
  const side     = String(req.body?.side || "").trim().toUpperCase();
  const game     = String(req.body?.game || "").trim();
  if (!username) return res.status(400).json({ error: "username required" });

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
      const exists = (memory.pvpEntries||[]).find(e => e.username === username);
      if (exists) return res.status(409).json({ error: "duplicate", entry: exists });
      const saved = { _id: String(Date.now()), ...doc };
      memory.pvpEntries.push(saved);
      scheduleSave();
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
      const list = [...(memory.pvpEntries||[])].sort((a,b)=> new Date(b.ts) - new Date(a.ts));
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
      const i = (memory.pvpEntries||[]).findIndex(e => e._id === id || e.username === id.toUpperCase());
      if (i < 0) return res.json({ success: false });
      memory.pvpEntries[i].status = status;
      scheduleSave();
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
      const before = (memory.pvpEntries||[]).length;
      memory.pvpEntries = (memory.pvpEntries||[]).filter(e => e._id !== id && e.username !== id.toUpperCase());
      scheduleSave();
      return res.json({ success: (memory.pvpEntries||[]).length !== before });
    }
  } catch (e) {
    console.error("[PVP] delete failed", e);
    return res.status(500).json({ error: "delete failed" });
  }
});

/* ===================== PVP Bracket + LIVE BG/Bonus ===================== */
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
    scheduleSave();
  }
  memory.live.pvp = builder;
  return builder;
}

app.get("/api/pvp/bracket", async (req, res) => {
  try { const builder = await getBracket(); res.json({ builder: builder
  try { const builder = await getBracket(); res.json({ builder: builder || null }); }
  catch (e) { console.error("[PVP] bracket read failed", e); res.status(500).json({ error: "failed" }); }
});

// Admin: save full builder (idempotent)
app.post("/api/admin/pvp/bracket/save", verifyAdminToken, async (req, res) => {
  try {
    const builder = req.body?.builder;
    if (!builder || typeof builder !== "object") return res.status(400).json({ error: "builder_required" });
    const saved = await saveBracket(builder);
    res.json({ success: true, builder: saved });
  } catch (e) {
    console.error("[PVP] bracket save failed", e);
    res.status(500).json({ error: "save_failed" });
  }
});

// Admin: quick-generate empty bracket
app.post("/api/admin/pvp/bracket/generate", verifyAdminToken, async (req, res) => {
  try {
    const size = Math.max(8, Number(req.body?.size || 8)); // must be power of 2 per side (we use 8 as base)
    const builder = {
      id: "active",
      east: buildEmptySide(size),
      west: buildEmptySide(size),
      final: {
        id: `final_${Math.random().toString(36).slice(2,8)}`,
        left: { name: "", img: "", score: null },
        right:{ name: "", img: "", score: null },
        status: "pending",
        winner: null,
        game: ""
      },
      lastUpdated: nowMs()
    };
    const saved = await saveBracket(builder);
    res.json({ success: true, builder: saved });
  } catch (e) {
    console.error("[PVP] generate failed", e);
    res.status(500).json({ error: "generate_failed" });
  }
});

// helpers to locate/advance matches
function findMatch(builder, matchId) {
  const scan = (sideName, rounds) => {
    for (let r = 0; r < rounds.length; r++) {
      const arr = rounds[r] || [];
      for (let i = 0; i < arr.length; i++) {
        if (arr[i]?.id === matchId) return { side: sideName, roundIndex: r, matchIndex: i, match: arr[i] };
      }
    }
    return null;
  };
  return (
    scan("east", builder?.east || []) ||
    scan("west", builder?.west || []) ||
    (builder?.final?.id === matchId ? { side: "final", roundIndex: 0, matchIndex: 0, match: builder.final } : null)
  );
}
function propagateWinner(builder, side, roundIndex, matchIndex) {
  const getRounds = (name) => (name === "east" ? builder.east : name === "west" ? builder.west : null);
  const rounds = getRounds(side);
  if (!rounds) return;

  const m = (rounds[roundIndex] || [])[matchIndex];
  if (!m || !m.winner) return;

  // Choose winner payload (name/img)
  const winnerPlayer = m.winner === "left" ? m.left : m.right;

  // If next round exists, move there; else to final
  if (roundIndex + 1 < rounds.length) {
    const next = rounds[roundIndex + 1];
    const target = nextIndex(matchIndex);
    const slot = matchIndex % 2 === 0 ? "left" : "right";
    putIntoSlot(next[target], slot, { name: winnerPlayer.name, img: winnerPlayer.img, score: null });
  } else {
    // move into final
    const slot = side === "east" ? "left" : "right";
    putIntoSlot(builder.final, slot, { name: winnerPlayer.name, img: winnerPlayer.img, score: null });
  }
}

// Admin: score a match + set winner + auto-advance
app.post("/api/admin/pvp/bracket/score", verifyAdminToken, async (req, res) => {
  try {
    const { matchId, leftScore, rightScore, game } = req.body || {};
    if (!matchId) return res.status(400).json({ error: "matchId_required" });

    const builder = await getBracket();
    if (!builder) return res.status(404).json({ error: "no_bracket" });

    const found = findMatch(builder, matchId);
    if (!found) return res.status(404).json({ error: "match_not_found" });

    // Update scores
    if (typeof leftScore === "number")  found.match.left.score = leftScore;
    if (typeof rightScore === "number") found.match.right.score = rightScore;
    if (game !== undefined) found.match.game = String(game || "");

    // Decide winner if both scores present
    if (Number.isFinite(found.match.left.score) && Number.isFinite(found.match.right.score)) {
      if (found.match.left.score > found.match.right.score) {
        found.match.winner = "left";
      } else if (found.match.right.score > found.match.left.score) {
        found.match.winner = "right";
      } else {
        found.match.winner = null; // tie -> require manual resolve
      }
      found.match.status = found.match.winner ? "done" : "pending";
      if (found.match.winner) propagateWinner(builder, found.side, found.roundIndex, found.matchIndex);
    }

    const saved = await saveBracket(builder);
    res.json({ success: true, builder: saved });
  } catch (e) {
    console.error("[PVP] score failed", e);
    res.status(500).json({ error: "score_failed" });
  }
});

// Admin: set a match winner explicitly and advance
app.post("/api/admin/pvp/bracket/winner", verifyAdminToken, async (req, res) => {
  try {
    const { matchId, winner /* 'left' | 'right' */ } = req.body || {};
    if (!matchId || !["left", "right"].includes(String(winner))) {
      return res.status(400).json({ error: "bad_params" });
    }
    const builder = await getBracket();
    if (!builder) return res.status(404).json({ error: "no_bracket" });

    const found = findMatch(builder, matchId);
    if (!found) return res.status(404).json({ error: "match_not_found" });

    found.match.winner = winner;
    found.match.status = "done";
    propagateWinner(builder, found.side, found.roundIndex, found.matchIndex);

    const saved = await saveBracket(builder);
    res.json({ success: true, builder: saved });
  } catch (e) {
    console.error("[PVP] winner failed", e);
    res.status(500).json({ error: "winner_failed" });
  }
});

/* ===================== LIVE: Battleground / Bonus widgets ===================== */
app.get("/api/live", (req, res) => {
  res.json({ ok: true, live: memory.live || {} });
});

app.get("/api/live/battleground", (req, res) => {
  res.json({ ok: true, battleground: memory.live?.battleground || null });
});
app.post("/api/admin/live/battleground", verifyAdminToken, (req, res) => {
  memory.live.battleground = { ...(req.body || {}), ts: nowMs() };
  scheduleSave();
  res.json({ ok: true });
});

app.get("/api/live/bonus", (req, res) => {
  res.json({ ok: true, bonus: memory.live?.bonus || null });
});
app.post("/api/admin/live/bonus", verifyAdminToken, (req, res) => {
  memory.live.bonus = { ...(req.body || {}), ts: nowMs() };
  scheduleSave();
  res.json({ ok: true });
});

/* ===================== PROMOS ===================== */
// Admin: create/update a promo code
app.post("/api/admin/promo/create", verifyAdminToken, (req, res) => {
  const b = req.body || {};
  const code = normCode(b.code || "");
  const amount = Number(b.amount || 0);
  const maxRedemptions = Number.isFinite(b.maxRedemptions) ? Number(b.maxRedemptions) : 0; // 0 = unlimited
  const expiresAt = b.expiresAt ? new Date(b.expiresAt).getTime() : 0;

  if (!code) return res.status(400).json({ error: "code_required" });
  if (!PROMO_ALLOWED_AMOUNTS.has(amount)) return res.status(400).json({ error: "invalid_amount" });

  const existingIdx = (memory.promoCodes || []).findIndex(p => p.code === code);
  const rec = { code, amount, maxRedemptions, expiresAt, updated: nowMs(), created: nowMs() };
  if (existingIdx >= 0) {
    memory.promoCodes[existingIdx] = { ...memory.promoCodes[existingIdx], ...rec };
  } else {
    memory.promoCodes.push(rec);
  }
  scheduleSave();
  res.json({ ok: true, promo: rec });
});

// Public: redeem
app.post("/api/promo/redeem", requireViewer, tinyRateLimit(), async (req, res) => {
  try {
    const code = normCode(req.body?.code || "");
    const user = req.viewer;
    if (!code) return res.status(400).json({ ok: false, error: "CODE_REQUIRED" });

    const promo = (memory.promoCodes || []).find(p => p.code === code);
    if (!promo) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
    if (promo.expiresAt && nowMs() > promo.expiresAt) return res.status(400).json({ ok: false, error: "EXPIRED" });

    const redemptions = memory.promoRedemptions || [];
    const userRedeemed = redemptions.some(r => r.code === code && r.user === user);
    if (userRedeemed) return res.status(409).json({ ok: false, error: "ALREADY_REDEEMED" });

    const totalRedeemed = redemptions.filter(r => r.code === code).length;
    if (promo.maxRedemptions && totalRedeemed >= promo.maxRedemptions) {
      return res.status(400).json({ ok: false, error: "MAXED_OUT" });
    }

    // credit wallet
    const adj = await adjustWallet(user, Number(promo.amount), `promo:${code}`);
    memory.promoRedemptions.push({ code, user, ts: nowMs() });
    scheduleSave();

    res.json({ ok: true, balance: adj.balance, applied: promo.amount });
  } catch (e) {
    console.error("[PROMO] redeem failed", e);
    res.status(500).json({ ok: false, error: "FAILED" });
  }
});

// Admin: inspect promo
app.get("/api/admin/promo/:code", verifyAdminToken, (req, res) => {
  const code = normCode(req.params.code || "");
  const promo = (memory.promoCodes || []).find(p => p.code === code) || null;
  const redemptions = (memory.promoRedemptions || []).filter(r => r.code === code);
  res.json({ ok: true, promo, redemptions });
});

/* ===================== BETS: drafts & publish ===================== */
// Admin: list drafts
app.get("/api/admin/bets/drafts", verifyAdminToken, (req, res) => {
  res.json({ drafts: memory.betsDrafts || [] });
});
// Admin: upsert draft
app.post("/api/admin/bets/drafts", verifyAdminToken, (req, res) => {
  const d = req.body || {};
  d._id = d._id || `draft_${Math.random().toString(36).slice(2,10)}`;
  d.updatedAt = nowMs();
  const i = (memory.betsDrafts || []).findIndex(x => x._id === d._id);
  if (i >= 0) memory.betsDrafts[i] = { ...memory.betsDrafts[i], ...d };
  else (memory.betsDrafts || (memory.betsDrafts = [])).unshift(d);
  scheduleSave();
  res.json({ ok: true, draft: d });
});
// Admin: delete draft
app.delete("/api/admin/bets/drafts/:id", verifyAdminToken, (req, res) => {
  const id = String(req.params.id || "");
  const before = (memory.betsDrafts || []).length;
  memory.betsDrafts = (memory.betsDrafts || []).filter(x => x._id !== id);
  scheduleSave();
  res.json({ ok: true, removed: before - (memory.betsDrafts || []).length });
});
// Admin: publish draft -> published
app.post("/api/admin/bets/publish/:id", verifyAdminToken, (req, res) => {
  const id = String(req.params.id || "");
  const i = (memory.betsDrafts || []).findIndex(x => x._id === id);
  if (i < 0) return res.status(404).json({ error: "draft_not_found" });
  const draft = memory.betsDrafts[i];
  const pub = {
    ...draft,
    status: "open",
    publishedAt: nowMs()
  };
  (memory.betsPublished || (memory.betsPublished = [])).unshift(pub);
  memory.betsDrafts.splice(i, 1);
  scheduleSave();
  res.json({ ok: true, published: pub });
});

// Public: list published bets
app.get("/api/bets", (req, res) => {
  const status = String(req.query.status || "open").toLowerCase();
  let items = memory.betsPublished || [];
  if (status !== "all") items = items.filter(b => String(b.status || "").toLowerCase() === status);
  res.json({ items });
});

// Admin: update published bet status
app.post("/api/admin/bets/published/:id/status", verifyAdminToken, (req, res) => {
  const id = String(req.params.id || "");
  const status = String(req.body?.status || "").toLowerCase(); // open | closed | settled
  const i = (memory.betsPublished || []).findIndex(x => x._id === id);
  if (i < 0) return res.status(404).json({ error: "not_found" });
  memory.betsPublished[i].status = status;
  memory.betsPublished[i].updatedAt = nowMs();
  scheduleSave();
  res.json({ ok: true });
});

/* ===================== DB / STATE INIT ===================== */
async function initStorage() {
  // Try Mongo first
  if (MONGO_URI) {
    try {
      const client = new MongoClient(MONGO_URI, { maxPoolSize: 8 });
      await client.connect();
      globalThis.__db = client.db(MONGO_DB);
      globalThis.__dbReady = true;
      storageMode = "mongo";
      console.log(`[DB] Connected to MongoDB (${MONGO_DB})`);
      return;
    } catch (e) {
      console.warn("[DB] Mongo connect failed:", e?.message || e);
    }
  }

  // File fallback
  if (STATE_PERSIST && ensureWritableStatePath()) {
    storageMode = "file";
    loadStateIfPresent();
    console.log(`[STATE] Using file persistence at ${STATE_FILE}`);
    return;
  }

  // Memory last resort
  if (ALLOW_MEMORY_FALLBACK) {
    storageMode = "memory";
    console.warn("[STATE] Falling back to in-memory storage (non-persistent).");
    return;
  }

  console.error("[STATE] No storage available and memory fallback disabled.");
  process.exit(1);
}

/* ===================== START SERVER ===================== */
initStorage().then(() => {
  const server = app.listen(PORT, HOST, () => {
    console.log(`[HTTP] listening on http://${HOST}:${PORT} (env=${NODE_ENV}, storage=${storageMode})`);
  });

  // graceful shutdown
  const shutdown = (sig) => () => {
    console.log(`[SYS] ${sig} received, shutting down...`);
    try { if (storageMode === "file") scheduleSave(); } catch {}
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000);
  };
  process.on("SIGINT",  shutdown("SIGINT"));
  process.on("SIGTERM", shutdown("SIGTERM"));
}).catch((e) => {
  console.error("[INIT] failed", e);
  process.exit(1);
});
