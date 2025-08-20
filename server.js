// server.js — hardened Express API for L3Z HUD (ESM, Node 20.x)
//
// What’s here (audit-aligned):
// - Trust proxy, secure cookies, CORS allowlist
// - Auth: signup/login/logout/me
// - Wallet: get, credit, debit, **adjust**, **balance (admin)**
// - Lucky7 award
// - Predictions submit
// - Leaderboard scaffold
// - Promo codes: create (admin), redeem (user), **HUD helpers** (issue/expire/my, admin redeem)
// - **Admin HUD**: gate/check/logout, feature flags, audit trail + export
// - Health
//
// Deps: express, dotenv, cookie-parser, cors, compression, helmet,
//       morgan, bcryptjs, jsonwebtoken, mongodb

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
import crypto from "crypto";
import { MongoClient, ObjectId } from "mongodb";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ===== Env
const NODE_ENV      = process.env.NODE_ENV || "production";
const PORT          = Number(process.env.PORT || process.env.PORT0 || 3000);
const MONGO_URI     = process.env.MONGO_URI || "";
const DB_NAME       = process.env.DB_NAME || "lash3z";
const JWT_SECRET    = process.env.SECRET || process.env.ADMIN_SECRET || "dev-secret";
const COOKIE_NAME   = process.env.COOKIE_NAME || "l3z_auth";
const COOKIE_SECURE = (process.env.COOKIE_SECURE ?? "true") !== "false";
const ADMIN_USER    = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS    = process.env.ADMIN_PASS || "";
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
  LeaderEvents = db.collection("leader_events"); // normalized scoring events
  AdminAudit   = db.collection("admin_audit");   // HUD audit trail
  AdminFlags   = db.collection("admin_flags");   // feature toggles

  // Indexes
  await Users.createIndex({ username: 1 }, { unique: true });
  await Users.createIndex({ email: 1 }, { unique: true, sparse: true });
  await Predictions.createIndex({ createdAt: -1 });
  await Codes.createIndex({ code: 1 }, { unique: true });
  await Codes.createIndex({ active: 1, expiresAt: 1 });
  await AdminAudit.createIndex({ createdAt: -1 });
  await AdminFlags.createIndex({ _id: 1 });

  // Seed flags doc if missing
  await AdminFlags.updateOne(
    { _id: "flags" },
    { $setOnInsert: { battleground:false, bonus:false, pvp:false, raffles:false, promos:true, updatedAt:new Date() } },
    { upsert: true }
  );

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
        createdAt: new Date(),
      });
    }
  }
}
await initDb();

// ===== Helpers
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
function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}
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

    const uname = String(username).toLowerCase().trim();
    if (!/^[a-z0-9_.-]{3,20}$/i.test(uname)) {
      return res.status(400).json({ error: "invalid_username" });
    }

    const existing = await Users.findOne({ username: uname });
    if (existing) return res.status(409).json({ error: "username_taken" });

    const hash = await bcrypt.hash(password, 10);
    const doc = {
      username: uname,
      email: email || null,
      password: hash,
      role: "user",
      lbx: 0,
      createdAt: new Date(),
    };
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

    const uname = String(username).toLowerCase().trim();
    const user = await Users.findOne({ username: uname });
    if (!user) return res.status(401).json({ error: "invalid_credentials" });

    const ok = await bcrypt.compare(password, user.password || "");
    if (!ok) return res.status(401).json({ error: "invalid_credentials" });

    const token = signJwt({ uid: user._id.toString(), role: user.role || "user" });
    setAuthCookie(res, token);

    res.json({
      ok: true,
      user: { _id: user._id, username: user.username, lbx: user.lbx || 0, role: user.role || "user" },
    });
  } catch (err) {
    res.status(500).json({ error: "login_failed", detail: err.message });
  }
});

app.post("/api/auth/logout", (_req, res) => { clearAuthCookie(res); res.json({ ok: true }); });

app.get("/api/me", requireAuth, (req, res) => {
  const { _id, username, role, lbx, email, createdAt } = req.user;
  res.json({ ok: true, user: { _id, username, role, lbx: lbx || 0, email: email || null, createdAt } });
});

// ===== Wallet (LBX)
app.get("/api/wallet", requireAuth, async (req, res) => {
  const fresh = await Users.findOne({ _id: req.user._id }, { projection: { lbx: 1 } });
  res.json({ ok: true, lbx: fresh?.lbx || 0 });
});

// Admin credit/debit (also used by Lucky7 award)
app.post("/api/wallet/credit", requireAdmin, async (req, res) => {
  try {
    const { username, amount, reason } = req.body || {};
    const amt = Number(amount);
    if (!username || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });
    const uname = String(username).toLowerCase().trim();

    const session = client.startSession();
    let newBal = 0;
    await session.withTransaction(async () => {
      const r = await Users.findOneAndUpdate(
        { username: uname },
        { $inc: { lbx: Math.max(amt, 0) } },
        { returnDocument: "after", session }
      );
      if (!r.value) throw new Error("user_not_found");
      newBal = r.value.lbx;

      await LeaderEvents.insertOne({
        type: "wallet_credit",
        username: uname,
        amount: Math.max(amt, 0),
        reason: reason || null,
        createdAt: new Date(),
      }, { session });
    });
    await session.endSession();

    res.json({ ok: true, user: { username: uname, lbx: newBal }, balance: newBal });
  } catch (err) {
    res.status(500).json({ error: "credit_failed", detail: err.message });
  }
});

app.post("/api/wallet/debit", requireAdmin, async (req, res) => {
  try {
    const { username, amount, reason } = req.body || {};
    const amt = Number(amount);
    if (!username || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });
    const uname = String(username).toLowerCase().trim();

    const session = client.startSession();
    let newBal = 0;
    await session.withTransaction(async () => {
      const r = await Users.findOneAndUpdate(
        { username: uname, lbx: { $gte: amt } },
        { $inc: { lbx: -Math.max(amt, 0) } },
        { returnDocument: "after", session }
      );
      if (!r.value) throw new Error("insufficient_funds_or_user");
      newBal = r.value.lbx;

      await LeaderEvents.insertOne({
        type: "wallet_debit",
        username: uname,
        amount: Math.max(amt, 0),
        reason: reason || null,
        createdAt: new Date(),
      }, { session });
    });
    await session.endSession();

    res.json({ ok: true, user: { username: uname, lbx: newBal }, balance: newBal });
  } catch (err) {
    res.status(500).json({ error: "debit_failed", detail: err.message });
  }
});

// NEW (audit): Adjust (±) and Balance (admin)
app.post("/api/wallet/adjust", requireAdmin, async (req, res) => {
  try {
    const { username, delta, reason } = req.body || {};
    const d = Number(delta);
    if (!username || !Number.isFinite(d)) return res.status(400).json({ error: "bad_input" });
    const uname = String(username).toLowerCase().trim();

    const session = client.startSession();
    let newBal = 0;
    await session.withTransaction(async () => {
      const user = await Users.findOne({ username: uname }, { projection: { lbx:1 }, session });
      if (!user) throw new Error("user_not_found");
      if (d < 0 && (user.lbx || 0) < Math.abs(d)) throw new Error("insufficient_funds");
      const r = await Users.findOneAndUpdate(
        { username: uname },
        { $inc: { lbx: d } },
        { returnDocument: "after", session }
      );
      newBal = r.value.lbx;

      await LeaderEvents.insertOne({
        type: d >= 0 ? "wallet_adjust_plus" : "wallet_adjust_minus",
        username: uname,
        amount: d,
        reason: reason || null,
        createdAt: new Date(),
      }, { session });
    });
    await session.endSession();

    res.json({ ok: true, balance: newBal });
  } catch (err) {
    res.status(400).json({ error: "adjust_failed", detail: err.message });
  }
});

app.get("/api/wallet/balance", requireAdmin, async (req, res) => {
  const uname = String(req.query.user || "").toLowerCase().trim();
  if (!uname) return res.status(400).json({ error: "missing_user" });
  const u = await Users.findOne({ username: uname }, { projection: { lbx: 1 } });
  if (!u) return res.status(404).json({ error: "user_not_found" });
  res.json({ ok: true, balance: u.lbx || 0 });
});

// ===== Lucky7 award → credits LBX
app.post("/api/lucky7/award", requireAdmin, async (req, res) => {
  try {
    const { username, lbx, matchId } = req.body || {};
    const amt = Number(lbx);
    if (!username || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });

    const uname = String(username).toLowerCase().trim();
    const session = client.startSession();
    let newBal = 0;
    await session.withTransaction(async () => {
      const r = await Users.findOneAndUpdate(
        { username: uname },
        { $inc: { lbx: amt } },
        { returnDocument: "after", session }
      );
      if (!r.value) throw new Error("user_not_found");
      newBal = r.value.lbx;

      await LeaderEvents.insertOne({
        type: "lucky7_award",
        username: uname,
        amount: amt,
        matchId: matchId || null,
        createdAt: new Date(),
      }, { session });
    });
    await session.endSession();

    res.json({ ok: true, user: { username: uname, lbx: newBal }, balance: newBal });
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

    await LeaderEvents.insertOne({
      type: "prediction_submit",
      username: req.user.username,
      points: 0,
      huntType,
      createdAt: new Date(),
    });

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "prediction_failed", detail: err.message });
  }
});

// ===== Overall Leaderboard (simple aggregation over LeaderEvents)
app.get("/api/leaderboard/overall", async (_req, res) => {
  try {
    const agg = await LeaderEvents.aggregate([
      { $match: { type: { $in: ["prediction_point", "pvp_point"] } } },
      { $group: { _id: "$username", total: { $sum: "$points" } } },
      { $sort: { total: -1, _id: 1 } },
      { $limit: 100 },
    ]).toArray();

    res.json({
      ok: true,
      leaderboard: agg.map((r, i) => ({ rank: i + 1, username: r._id, total: r.total })),
    });
  } catch (err) {
    res.status(500).json({ error: "leaderboard_failed", detail: err.message });
  }
});

// ===== Promo Codes (classic user flow remains)
app.post("/api/code/create", requireAdmin, async (req, res) => {
  try {
    const { code, lbx, expiresHours } = req.body || {};
    const amt = Number(lbx);
    if (!code || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });

    const normalized = String(code).trim().toUpperCase();
    const hours = Math.max(1, Number(expiresHours || 48));
    const now = new Date();
    const expiresAt = new Date(now.getTime() + hours * 60 * 60 * 1000);

    await Codes.insertOne({
      code: normalized,
      lbx: amt,
      createdAt: now,
      expiresAt,
      redeemedBy: [], // usernames
      active: true,
    });

    res.json({ ok: true, code: normalized, lbx: amt, expiresAt });
  } catch (err) {
    if (String(err.message || "").includes("duplicate key")) {
      return res.status(409).json({ error: "code_exists" });
    }
    res.status(500).json({ error: "code_create_failed", detail: err.message });
  }
});

app.post("/api/code/redeem", requireAuth, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ error: "missing_code" });

    const normalized = String(code).trim().toUpperCase();
    const now = new Date();

    const c = await Codes.findOne({ code: normalized, active: true });
    if (!c) return res.status(404).json({ error: "invalid_code" });
    if (c.expiresAt && now > new Date(c.expiresAt)) {
      return res.status(410).json({ error: "code_expired" });
    }
    if ((c.redeemedBy || []).includes(req.user.username)) {
      return res.status(409).json({ error: "already_redeemed" });
    }

    const session = client.startSession();
    let newBalance = null;
    await session.withTransaction(async () => {
      await Users.updateOne(
        { _id: req.user._id },
        { $inc: { lbx: c.lbx } },
        { session }
      );

      await Codes.updateOne(
        { _id: c._id },
        { $addToSet: { redeemedBy: req.user.username } },
        { session }
      );

      const fresh = await Users.findOne({ _id: req.user._id }, { projection: { lbx: 1 }, session });
      newBalance = fresh?.lbx ?? null;

      await LeaderEvents.insertOne({
        type: "promo_credit",
        username: req.user.username,
        amount: c.lbx,
        code: c.code,
        createdAt: new Date(),
      }, { session });
    });
    await session.endSession();

    res.json({ ok: true, lbx: newBalance });
  } catch (err) {
    res.status(500).json({ error: "redeem_failed", detail: err.message });
  }
});

// ===== Admin HUD — gate/check/logout
app.get("/api/admin/gate/check", requireAdmin, (req, res) => {
  res.json({ ok: true, username: req.user.username, role: req.user.role });
});
app.post("/api/admin/gate/logout", (_req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

// ===== Admin HUD — Promo helpers (my/issue/expire + admin redeem)
app.get("/api/promo/my", requireAdmin, async (_req, res) => {
  const now = new Date();
  const c = await Codes.findOne(
    { active: true, expiresAt: { $gt: now } },
    { sort: { createdAt: -1 }, projection: { code: 1, lbx: 1, expiresAt: 1 } }
  );
  res.json({ ok: true, ...(c ? { code: c.code, lbx: c.lbx, expiresAt: c.expiresAt } : {}) });
});

app.post("/api/promo/issue", requireAdmin, async (req, res) => {
  try {
    const { lbx, ttlHours, replace } = req.body || {};
    const amt = Number(lbx);
    const hours = Math.max(1, Number(ttlHours || 48));
    if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });

    if (replace) {
      await Codes.updateMany({ active: true }, { $set: { active: false } });
    }

    const gen = () => crypto.randomUUID().replace(/-/g, "").slice(0, 8).toUpperCase();
    let code = gen();
    for (let i = 0; i < 3; i++) {
      const exists = await Codes.findOne({ code });
      if (!exists) break;
      code = gen();
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + hours * 3600_000);
    await Codes.insertOne({
      code,
      lbx: amt,
      createdAt: now,
      expiresAt,
      redeemedBy: [],
      active: true,
    });

    res.json({ ok: true, code, lbx: amt, expiresAt });
  } catch (err) {
    res.status(500).json({ error: "promo_issue_failed", detail: err.message });
  }
});

app.post("/api/promo/expire", requireAdmin, async (_req, res) => {
  const r = await Codes.updateMany({ active: true }, { $set: { active: false } });
  res.json({ ok: true, n: r.modifiedCount });
});

app.post("/api/promo/redeem", requireAdmin, async (req, res) => {
  try {
    const { username, code } = req.body || {};
    if (!username || !code) return res.status(400).json({ error: "missing_fields" });

    const uname = String(username).toLowerCase().trim();
    const normalized = String(code).trim().toUpperCase();
    const now = new Date();

    const c = await Codes.findOne({ code: normalized, active: true });
    if (!c) return res.status(404).json({ error: "invalid_code" });
    if (c.expiresAt && now > new Date(c.expiresAt)) return res.status(410).json({ error: "code_expired" });
    if ((c.redeemedBy || []).includes(uname)) return res.status(409).json({ error: "already_redeemed" });

    const session = client.startSession();
    let newBal = 0;
    await session.withTransaction(async () => {
      const r = await Users.findOneAndUpdate(
        { username: uname },
        { $inc: { lbx: c.lbx } },
        { returnDocument: "after", session }
      );
      if (!r.value) throw new Error("user_not_found");
      newBal = r.value.lbx;

      await Codes.updateOne(
        { _id: c._id },
        { $addToSet: { redeemedBy: uname } },
        { session }
      );

      await LeaderEvents.insertOne({
        type: "promo_credit_admin",
        username: uname,
        amount: c.lbx,
        code: c.code,
        createdAt: new Date(),
      }, { session });
    });
    await session.endSession();

    res.json({ ok: true, lbx: newBal });
  } catch (err) {
    const msg = /user_not_found/i.test(err.message || "") ? "user_not_found" : "redeem_failed";
    res.status(500).json({ error: msg, detail: err.message });
  }
});

// ===== Admin HUD — Feature Flags
app.get("/api/admin/flags/get", requireAdmin, async (_req, res) => {
  const f = await AdminFlags.findOne({ _id: "flags" }) || {};
  const { battleground=false, bonus=false, pvp=false, raffles=false, promos=true } = f;
  res.json({ ok: true, flags: { battleground, bonus, pvp, raffles, promos } });
});

app.post("/api/admin/flags/set", requireAdmin, async (req, res) => {
  const { flags = {} } = req.body || {};
  await AdminFlags.updateOne(
    { _id: "flags" },
    { $set: { ...flags, updatedAt: new Date() } },
    { upsert: true }
  );
  res.json({ ok: true });
});

app.post("/api/admin/flags/disable_all", requireAdmin, async (_req, res) => {
  const flags = { battleground:false, bonus:false, pvp:false, raffles:false, promos:false };
  await AdminFlags.updateOne(
    { _id: "flags" },
    { $set: { ...flags, updatedAt: new Date() } },
    { upsert: true }
  );
  res.json({ ok: true, flags });
});

app.post("/api/admin/flags/enable_all", requireAdmin, async (_req, res) => {
  const flags = { battleground:true, bonus:true, pvp:true, raffles:true, promos:true };
  await AdminFlags.updateOne(
    { _id: "flags" },
    { $set: { ...flags, updatedAt: new Date() } },
    { upsert: true }
  );
  res.json({ ok: true, flags });
});

// ===== Admin HUD — Audit
app.post("/api/admin/audit/track", requireAdmin, async (req, res) => {
  const { evt, payload } = req.body || {};
  await AdminAudit.insertOne({
    evt: String(evt || "").slice(0, 64),
    payload: payload || null,
    by: req.user.username,
    createdAt: new Date(),
  });
  res.json({ ok: true });
});

app.get("/api/admin/audit/list", requireAdmin, async (_req, res) => {
  const recs = await AdminAudit.find({}, { sort: { createdAt: -1 }, limit: 500 }).toArray();
  res.json({ ok: true, records: recs });
});

app.post("/api/admin/audit/clear", requireAdmin, async (_req, res) => {
  await AdminAudit.deleteMany({});
  res.json({ ok: true });
});

app.get("/api/admin/audit/export", requireAdmin, async (_req, res) => {
  const recs = await AdminAudit.find({}, { sort: { createdAt: 1 } }).toArray();
  const blob = JSON.stringify(recs, null, 2);
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="l3z_admin_audit_${Date.now()}.json"`);
  res.send(blob);
});

// ===== Error handler (last)
app.use((err, _req, res, _next) => {
  const code = err.status || 500;
  res.status(code).json({ error: "server_error", detail: err.message || String(err) });
});

// ===== Start
app.listen(PORT, () => {
  console.log(`[L3Z] API listening on :${PORT} (${NODE_ENV})`);
});
