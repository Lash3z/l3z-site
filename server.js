// server.js — hardened Express API for L3Z HUD (ESM, Node 20+)
import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import compression from "compression";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ===== Env
const NODE_ENV       = process.env.NODE_ENV || "production";
const PORT           = Number(process.env.PORT || process.env.PORT0 || 3000);
const MONGO_URI      = process.env.MONGO_URI || "";
const DB_NAME        = process.env.DB_NAME || "lash3z";
const JWT_SECRET     = process.env.SECRET || process.env.ADMIN_SECRET || "dev-secret";
const COOKIE_NAME    = process.env.COOKIE_NAME || "l3z_auth";
const COOKIE_SECURE  = (process.env.COOKIE_SECURE ?? "true") !== "false";
const ADMIN_USER     = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS     = process.env.ADMIN_PASS || "";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);

// ===== App
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

// ===== Security & parsing
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(compression());

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("CORS: origin not allowed"), false);
  },
  credentials: true,
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan(NODE_ENV === "production" ? "combined" : "dev"));

// ===== Mongo
let client, db, Users, Predictions, Codes, LeaderEvents, AdminAudit, AdminFlags;
async function initDb() {
  client = new MongoClient(MONGO_URI);
  await client.connect();
  db = client.db(DB_NAME);

  Users        = db.collection("users");
  Predictions  = db.collection("predictions");
  Codes        = db.collection("promo_codes");
  LeaderEvents = db.collection("leader_events");
  AdminAudit   = db.collection("admin_audit");
  AdminFlags   = db.collection("admin_flags");

  await Users.createIndex({ username: 1 }, { unique: true });
  await Users.createIndex({ email: 1 }, { unique: true, sparse: true });
  await Predictions.createIndex({ createdAt: -1 });
  await Codes.createIndex({ code: 1 }, { unique: true });
  await Codes.createIndex({ expiresAt: 1 });
  await AdminAudit.createIndex({ createdAt: -1 });

  // Ensure admin exists
  if (ADMIN_PASS) {
    const existing = await Users.findOne({ username: ADMIN_USER });
    if (!existing) {
      const hash = await bcrypt.hash(ADMIN_PASS, 10);
      await Users.insertOne({
        username: ADMIN_USER,
        password: hash,
        role: "admin",
        lbx: 0,
        wallet: { balance: 0 },
        createdAt: new Date(),
      });
    }
  }
}
await initDb();

// ===== Helpers
const norm = s => String(s || "").trim().toLowerCase();

function signJwt(payload, days = 7) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: `${days}d` });
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: COOKIE_SECURE,
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}
function clearAuthCookie(res) { res.clearCookie(COOKIE_NAME, { path: "/" }); }

async function authMiddleware(req, _res, next) {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (!token) return next();
    const data = jwt.verify(token, JWT_SECRET);
    if (!data?.uid) return next();
    req.user = await Users.findOne(
      { _id: new ObjectId(data.uid) },
      { projection: { password: 0 } }
    );
  } catch { /* ignore */ }
  next();
}
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "auth_required" });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "admin_required" });
  }
  next();
}
app.use(authMiddleware);

// ===== Health
app.get("/health", (_req, res) => res.json({ ok: true, env: NODE_ENV }));

// ===== Auth
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, password, email } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "missing_fields" });
    const uname = norm(username);
    if (!/^[a-z0-9_.-]{3,20}$/i.test(uname)) return res.status(400).json({ error: "invalid_username" });
    const existing = await Users.findOne({ username: uname });
    if (existing) return res.status(409).json({ error: "username_taken" });

    const hash = await bcrypt.hash(password, 10);
    const doc = { username: uname, email: email || null, password: hash, role: "user", lbx: 0, wallet: { balance: 0 }, createdAt: new Date() };
    const { insertedId } = await Users.insertOne(doc);

    const token = signJwt({ uid: insertedId.toString(), role: "user" });
    setAuthCookie(res, token);
    res.json({ ok: true, user: { _id: insertedId, username: uname, lbx: 0, role: "user" } });
  } catch (err) {
    res.status(500).json({ error: "signup_failed", detail: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "missing_fields" });
    const uname = norm(username);
    const user = await Users.findOne({ username: uname });
    if (!user) return res.status(401).json({ error: "invalid_credentials" });
    const ok = await bcrypt.compare(password, user.password || "");
    if (!ok) return res.status(401).json({ error: "invalid_credentials" });

    const token = signJwt({ uid: user._id.toString(), role: user.role || "user" });
    setAuthCookie(res, token);
    res.json({ ok: true, user: { _id: user._id, username: user.username, lbx: user.lbx || user.wallet?.balance || 0, role: user.role || "user" } });
  } catch (err) {
    res.status(500).json({ error: "login_failed", detail: err.message });
  }
});
app.post("/api/auth/logout", (req, res) => { clearAuthCookie(res); res.json({ ok: true }); });
app.get("/api/me", requireAuth, (req, res) => {
  const { _id, username, role, lbx, wallet, email, createdAt } = req.user;
  const bal = Number(lbx ?? wallet?.balance ?? 0);
  res.json({ ok: true, user: { _id, username, role, lbx: bal, email: email || null, createdAt } });
});

// ===== Wallet (LBX)
app.get("/api/wallet", requireAuth, async (req, res) => {
  try {
    // backward-compat: admin can query specific username
    const qUser = norm(req.query.username || "");
    const target = (qUser && req.user.role === "admin") ? await Users.findOne({ username: qUser }) : await Users.findOne({ _id: req.user._id });
    const bal = Number(target?.lbx ?? target?.wallet?.balance ?? 0);
    res.json({ ok: true, lbx: bal });
  } catch (err) {
    res.status(500).json({ error: "wallet_failed", detail: err.message });
  }
});

app.post("/api/wallet/credit", requireAdmin, async (req, res) => {
  try {
    const { username, amount, reason } = req.body || {};
    const amt = Math.max(0, Number(amount));
    if (!username || !Number.isFinite(amt)) return res.status(400).json({ error: "bad_input" });
    const uname = norm(username);

    const r = await Users.findOneAndUpdate(
      { username: uname },
      { $inc: { lbx: amt, "wallet.balance": amt } },
      { returnDocument: "after" }
    );
    if (!r.value) return res.status(404).json({ error: "user_not_found" });

    await LeaderEvents.insertOne({ type: "wallet_credit", username: uname, amount: amt, reason: reason || null, createdAt: new Date() });
    res.json({ ok: true, user: { username: uname, lbx: Number(r.value.lbx ?? r.value.wallet?.balance ?? 0) } });
  } catch (err) {
    res.status(500).json({ error: "credit_failed", detail: err.message });
  }
});

app.post("/api/wallet/debit", requireAdmin, async (req, res) => {
  try {
    const { username, amount, reason } = req.body || {};
    const amt = Math.max(0, Number(amount));
    if (!username || !Number.isFinite(amt)) return res.status(400).json({ error: "bad_input" });
    const uname = norm(username);

    // Only debit if funds available
    const user = await Users.findOne({ username: uname }, { projection: { lbx: 1, wallet: 1 } });
    const current = Number(user?.lbx ?? user?.wallet?.balance ?? 0);
    if (current < amt) return res.status(400).json({ error: "insufficient_funds_or_user" });

    const r = await Users.findOneAndUpdate(
      { username: uname },
      { $inc: { lbx: -amt, "wallet.balance": -amt } },
      { returnDocument: "after" }
    );
    await LeaderEvents.insertOne({ type: "wallet_debit", username: uname, amount: amt, reason: reason || null, createdAt: new Date() });
    res.json({ ok: true, user: { username: uname, lbx: Number(r.value.lbx ?? r.value.wallet?.balance ?? 0) } });
  } catch (err) {
    res.status(500).json({ error: "debit_failed", detail: err.message });
  }
});

// ===== Admin Wallet helpers
app.get("/api/admin/wallet/balance", requireAdmin, async (req, res) => {
  const uname = norm(req.query.user || "");
  if (!uname) return res.status(400).json({ error: "missing_user" });
  const u = await Users.findOne({ username: uname }, { projection: { lbx: 1, wallet: 1 } });
  const bal = Number(u?.lbx ?? u?.wallet?.balance ?? 0);
  res.json({ ok: true, username: uname, balance: bal, lbx: bal });
});

// ===== Lucky7 award → credits LBX
app.post("/api/lucky7/award", requireAdmin, async (req, res) => {
  try {
    const { username, lbx, matchId } = req.body || {};
    const amt = Number(lbx);
    if (!username || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });
    const uname = norm(username);

    const r = await Users.findOneAndUpdate(
      { username: uname },
      { $inc: { lbx: amt, "wallet.balance": amt } },
      { returnDocument: "after" }
    );
    if (!r.value) return res.status(404).json({ error: "user_not_found" });

    await LeaderEvents.insertOne({ type: "lucky7_award", username: uname, amount: amt, matchId: matchId || null, createdAt: new Date() });
    res.json({ ok: true, user: { username: uname, lbx: Number(r.value.lbx ?? r.value.wallet?.balance ?? 0) } });
  } catch (err) {
    res.status(500).json({ error: "award_failed", detail: err.message });
  }
});

// ===== Predictions (placeholder)
app.post("/api/predictions/submit", requireAuth, async (req, res) => {
  try {
    const { huntType, hundredX, topGame, profitYesNo } = req.body || {};
    if (!huntType || !topGame) return res.status(400).json({ error: "missing_fields" });

    await Predictions.insertOne({
      username: req.user.username,
      huntType,
      hundredX: Number(hundredX ?? 0),
      topGame: String(topGame),
      profitYesNo: typeof profitYesNo === "boolean" ? profitYesNo : null,
      createdAt: new Date(),
    });

    await LeaderEvents.insertOne({ type: "prediction_submit", username: req.user.username, points: 0, huntType, createdAt: new Date() });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "prediction_failed", detail: err.message });
  }
});

// ===== Overall Leaderboard
app.get("/api/leaderboard/overall", async (_req, res) => {
  try {
    const agg = await LeaderEvents.aggregate([
      { $match: { type: { $in: ["prediction_point", "pvp_point"] } } },
      { $group: { _id: "$username", total: { $sum: "$points" } } },
      { $sort: { total: -1, _id: 1 } },
      { $limit: 100 },
    ]).toArray();

    res.json({ ok: true, leaderboard: agg.map((r, i) => ({ rank: i + 1, username: r._id, total: r.total })) });
  } catch (err) {
    res.status(500).json({ error: "leaderboard_failed", detail: err.message });
  }
});

// ===== Promo Codes
// Create code (ADMIN): body { code, lbx, expiresHours }
app.post("/api/code/create", requireAdmin, async (req, res) => {
  try {
    const { code, lbx, expiresHours } = req.body || {};
    const amt = Number(lbx);
    if (!code || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });

    const normalized = String(code).trim().toUpperCase();
    const hours = Math.max(1, Number(expiresHours || 48));
    const now = new Date();
    const expiresAt = new Date(now.getTime() + hours * 60 * 60 * 1000);

    await Codes.insertOne({ code: normalized, lbx: amt, createdAt: now, expiresAt, redeemedBy: [], active: true });
    res.json({ ok: true, code: normalized, lbx: amt, expiresAt });
  } catch (err) {
    if (String(err.message || "").includes("duplicate key")) return res.status(409).json({ error: "code_exists" });
    res.status(500).json({ error: "code_create_failed", detail: err.message });
  }
});

// Admin: current active code (latest)
app.get("/api/admin/code/current", requireAdmin, async (_req, res) => {
  const c = await Codes.findOne({ active: true }, { sort: { createdAt: -1 } });
  if (!c) return res.json({ ok: true, code: null });
  res.json({ ok: true, code: c.code, lbx: c.lbx, expiresAt: c.expiresAt });
});

// User: redeem own code
app.post("/api/code/redeem", requireAuth, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ error: "missing_code" });
    const normalized = String(code).trim().toUpperCase();
    const now = new Date();

    const c = await Codes.findOne({ code: normalized, active: true });
    if (!c) return res.status(404).json({ error: "invalid_code" });
    if (c.expiresAt && now > new Date(c.expiresAt)) return res.status(410).json({ error: "code_expired" });
    if ((c.redeemedBy || []).includes(req.user.username)) return res.status(409).json({ error: "already_redeemed" });

    const session = client.startSession();
    let newBalance = null;
    await session.withTransaction(async () => {
      await Users.updateOne({ _id: req.user._id }, { $inc: { lbx: c.lbx, "wallet.balance": c.lbx } }, { session });
      await Codes.updateOne({ _id: c._id }, { $addToSet: { redeemedBy: req.user.username } }, { session });
      const fresh = await Users.findOne({ _id: req.user._id }, { projection: { lbx: 1, wallet: 1 }, session });
      newBalance = Number(fresh?.lbx ?? fresh?.wallet?.balance ?? 0);
      await LeaderEvents.insertOne({ type: "promo_credit", username: req.user.username, amount: c.lbx, code: c.code, createdAt: new Date() }, { session });
    });
    await session.endSession();
    res.json({ ok: true, lbx: newBalance });
  } catch (err) {
    res.status(500).json({ error: "redeem_failed", detail: err.message });
  }
});

// Admin: redeem code for a specific user
app.post("/api/admin/code/redeem_for", requir_
