// server.js — L3Z API + Static Host (ESM, Node 20)
// - Auth (signup/login/logout/me) with HttpOnly cookie JWT
// - Wallet LBX (user get, admin credit/debit, admin balance)
// - Bets (player place/list; admin list/settle/void/bulk)
// - Promo Codes (create/admin-current/admin-expire/user-redeem/admin-redeem_for)
// - Feature Flags (admin get/set/enable_all/disable_all)
// - Audit (track/list/export/clear)
// - Kick (stub) link/unlink/status
// - CORS allowlist + cookie SameSite tuned for cross-origin on Render
// - **Static hosting enabled** (serves /assets, /pages, /admin, etc.)
//   Root redirects: "/" -> "/pages/profile.html", "/admin" -> "/admin/login.html"
//
// ENV:
//   NODE_ENV, PORT / PORT0
//   MONGO_URI, DB_NAME
//   SECRET or ADMIN_SECRET (JWT secret)
//   COOKIE_NAME (default l3z_auth)
//   COOKIE_SECURE ("true"/"false") default true
//   COOKIE_SAMESITE ("lax"|"none"|"strict") default auto: "none" when ALLOWED_ORIGINS set, else "lax"
//   ADMIN_USER, ADMIN_PASS (bootstrap an admin)
//   ALLOWED_ORIGINS (comma-separated e.g. https://your-site.onrender.com,https://www.yourdomain.com)
//   KICK_LINK_URL (optional; where to send user to link Kick)

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
const NODE_ENV         = process.env.NODE_ENV || "production";
const PORT             = Number(process.env.PORT || process.env.PORT0 || 3000);
const MONGO_URI        = process.env.MONGO_URI || "";
const DB_NAME          = process.env.DB_NAME || "lash3z";
const JWT_SECRET       = process.env.SECRET || process.env.ADMIN_SECRET || "dev-secret";
const COOKIE_NAME      = process.env.COOKIE_NAME || "l3z_auth";
const COOKIE_SECURE    = (process.env.COOKIE_SECURE ?? "true") !== "false";
const ALLOWED_ORIGINS  = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);
const COOKIE_SAMESITE  = (process.env.COOKIE_SAMESITE ||
  (ALLOWED_ORIGINS.length ? "none" : "lax")).toLowerCase(); // "none" for cross-origin auth
const ADMIN_USER       = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS       = process.env.ADMIN_PASS || "";
const KICK_LINK_URL    = process.env.KICK_LINK_URL || "https://kick.com/";

// ===== App
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

// ===== Security & parsing
app.use(helmet({
  contentSecurityPolicy: false, // keep inline scripts/styles working
  crossOriginEmbedderPolicy: false,
}));
app.use(compression());

// CORS — allow cookie auth for HUD + widget origins
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // same-origin / curl
    if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("CORS: origin not allowed"));
  },
  credentials: true,
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan(NODE_ENV === "production" ? "combined" : "dev"));

// ===== Mongo
let client, db;
let Users, Bets, Codes, LeaderEvents, AdminFlags, AdminAudit, Predictions;
async function initDb() {
  client = new MongoClient(MONGO_URI);
  await client.connect();
  db = client.db(DB_NAME);

  Users        = db.collection("users");
  Bets         = db.collection("bets");
  Codes        = db.collection("promo_codes");
  LeaderEvents = db.collection("leader_events");
  AdminFlags   = db.collection("admin_flags");
  AdminAudit   = db.collection("admin_audit");
  Predictions  = db.collection("predictions"); // reserved

  // Indexes
  await Users.createIndex({ username: 1 }, { unique: true });
  await Users.createIndex({ email: 1 }, { unique: true, sparse: true });

  await Bets.createIndex({ createdAt: -1 });
  await Bets.createIndex({ status: 1, createdAt: -1 });
  await Bets.createIndex({ username: 1, createdAt: -1 });

  await Codes.createIndex({ code: 1 }, { unique: true });
  await Codes.createIndex({ expiresAt: 1 });

  await AdminAudit.createIndex({ createdAt: -1 });

  // Bootstrap admin
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
function sameSiteValue(s) {
  const v = String(s || "").toLowerCase();
  return v === "none" ? "none" : (v === "strict" ? "strict" : "lax");
}
function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: sameSiteValue(COOKIE_SAMESITE),
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
    const user = await Users.findOne({ _id: new ObjectId(data.uid) });
    if (user) {
      delete user.password;
      req.user = user;
    }
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
const n = v => (Number.isFinite(Number(v)) ? Number(v) : NaN);

// mount auth early so static pages can use cookies
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
      kick: null,
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

app.post("/api/auth/logout", (req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  const { _id, username, role, lbx, email, createdAt, kick } = req.user;
  res.json({ ok: true, user: { _id, username, role, lbx: lbx || 0, email: email || null, createdAt, kick: kick || null } });
});

// ===== Wallet (LBX)
app.get("/api/wallet", requireAuth, async (req, res) => {
  const fresh = await Users.findOne({ _id: req.user._id }, { projection: { lbx: 1 } });
  res.json({ ok: true, lbx: fresh?.lbx || 0 });
});

// Admin credit/debit
app.post("/api/wallet/credit", requireAdmin, async (req, res) => {
  try {
    const { username, amount, reason } = req.body || {};
    const amt = n(amount);
    if (!username || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });
    const uname = String(username).toLowerCase().trim();

    const r = await Users.findOneAndUpdate(
      { username: uname },
      { $inc: { lbx: Math.max(amt, 0) } },
      { returnDocument: "after" }
    );
    if (!r.value) return res.status(404).json({ error: "user_not_found" });

    await LeaderEvents.insertOne({
      type: "wallet_credit",
      username: uname,
      amount: Math.max(amt, 0),
      reason: reason || null,
      createdAt: new Date(),
    });

    await AdminAudit.insertOne({
      actor: req.user.username, evt: "wallet.credit",
      payload: { username: uname, amount: amt, reason: reason || null },
      createdAt: new Date(),
    });

    res.json({ ok: true, user: { username: uname, lbx: r.value.lbx } });
  } catch (err) {
    res.status(500).json({ error: "credit_failed", detail: err.message });
  }
});

app.post("/api/wallet/debit", requireAdmin, async (req, res) => {
  try {
    const { username, amount, reason } = req.body || {};
    const amt = n(amount);
    if (!username || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });
    const uname = String(username).toLowerCase().trim();

    const r = await Users.findOneAndUpdate(
      { username: uname, lbx: { $gte: amt } },
      { $inc: { lbx: -Math.max(amt, 0) } },
      { returnDocument: "after" }
    );
    if (!r.value) return res.status(400).json({ error: "insufficient_funds_or_user" });

    await LeaderEvents.insertOne({
      type: "wallet_debit",
      username: uname,
      amount: Math.max(amt, 0),
      reason: reason || null,
      createdAt: new Date(),
    });

    await AdminAudit.insertOne({
      actor: req.user.username, evt: "wallet.debit",
      payload: { username: uname, amount: amt, reason: reason || null },
      createdAt: new Date(),
    });

    res.json({ ok: true, user: { username: uname, lbx: r.value.lbx } });
  } catch (err) {
    res.status(500).json({ error: "debit_failed", detail: err.message });
  }
});

// Admin balance check
app.get("/api/admin/wallet/balance", requireAdmin, async (req, res) => {
  const uname = String(req.query.user || "").toLowerCase().trim();
  if (!uname) return res.status(400).json({ error: "missing_user" });
  const u = await Users.findOne({ username: uname }, { projection: { lbx: 1 } });
  if (!u) return res.status(404).json({ error: "user_not_found" });
  res.json({ ok: true, username: uname, balance: u.lbx || 0 });
});

// ===== Promo Codes
app.post("/api/code/create", requireAdmin, async (req, res) => {
  try {
    const { code, lbx, expiresHours } = req.body || {};
    const amt = n(lbx);
    if (!code || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "bad_input" });

    const normalized = String(code).trim().toUpperCase();
    const hours = Math.max(1, n(expiresHours || 48));
    const now = new Date();
    const expiresAt = new Date(now.getTime() + hours * 60 * 60 * 1000);

    await Codes.insertOne({
      code: normalized,
      lbx: amt,
      createdAt: now,
      expiresAt,
      redeemedBy: [],
      active: true,
    });

    await AdminAudit.insertOne({
      actor: req.user.username, evt: "promo.issue",
      payload: { code: normalized, lbx: amt, expiresAt },
      createdAt: new Date(),
    });

    res.json({ ok: true, code: normalized, lbx: amt, expiresAt });
  } catch (err) {
    if (String(err.message || "").includes("duplicate key")) {
      return res.status(409).json({ error: "code_exists" });
    }
    res.status(500).json({ error: "code_create_failed", detail: err.message });
  }
});

app.get("/api/admin/code/current", requireAdmin, async (_req, res) => {
  const now = new Date();
  const cur = await Codes.find({ active: true, expiresAt: { $gt: now } })
    .sort({ createdAt: -1 }).limit(1).toArray();
  const c = cur[0] || null;
  res.json(c ? { ok: true, code: c.code, lbx: c.lbx, expiresAt: c.expiresAt } : { ok: true, code: null });
});

app.post("/api/admin/code/expire", requireAdmin, async (_req, res) => {
  const r = await Codes.updateMany({ active: true }, { $set: { active: false } });
  await AdminAudit.insertOne({
    actor: req.user.username, evt: "promo.expire",
    payload: { n: r.modifiedCount }, createdAt: new Date(),
  });
  res.json({ ok: true, n: r.modifiedCount });
});

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
      await Users.updateOne({ _id: req.user._id }, { $inc: { lbx: c.lbx } }, { session });
      await Codes.updateOne({ _id: c._id }, { $addToSet: { redeemedBy: req.user.username } }, { session });
      const fresh = await Users.findOne({ _id: req.user._id }, { projection: { lbx: 1 }, session });
      newBalance = fresh?.lbx ?? null;
      await LeaderEvents.insertOne({ type: "promo_credit", username: req.user.username, amount: c.lbx, code: c.code, createdAt: new Date() }, { session });
    });
    await session.endSession();

    res.json({ ok: true, lbx: newBalance });
  } catch (err) {
    res.status(500).json({ error: "redeem_failed", detail: err.message });
  }
});

app.post("/api/admin/code/redeem_for", requireAdmin, async (req, res) => {
  try {
    const { username, code } = req.body || {};
    const uname = String(username || "").toLowerCase().trim();
    if (!uname || !code) return res.status(400).json({ error: "bad_input" });

    const u = await Users.findOne({ username: uname }, { projection: { _id: 1 } });
    if (!u) return res.status(404).json({ error: "user_not_found" });

    const normalized = String(code).trim().toUpperCase();
    const now = new Date();
    const c = await Codes.findOne({ code: normalized, active: true });
    if (!c) return res.status(404).json({ error: "invalid_code" });
    if (c.expiresAt && now > new Date(c.expiresAt)) return res.status(410).json({ error: "code_expired" });
    if ((c.redeemedBy || []).includes(uname)) return res.status(409).json({ error: "already_redeemed" });

    const session = client.startSession();
    let newBalance = null;
    await session.withTransaction(async () => {
      await Users.updateOne({ _id: u._id }, { $inc: { lbx: c.lbx } }, { session });
      await Codes.updateOne({ _id: c._id }, { $addToSet: { redeemedBy: uname } }, { session });
      const fresh = await Users.findOne({ _id: u._id }, { projection: { lbx: 1 }, session });
      newBalance = fresh?.lbx ?? null;
      await LeaderEvents.insertOne({ type: "promo_credit_admin", username: uname, amount: c.lbx, code: c.code, createdAt: new Date() }, { session });
      await AdminAudit.insertOne({ actor: req.user.username, evt: "promo.redeem_for", payload: { username: uname, code: c.code, lbx: c.lbx }, createdAt: new Date() }, { session });
    });
    await session.endSession();

    res.json({ ok: true, lbx: newBalance });
  } catch (err) {
    res.status(500).json({ error: "redeem_for_failed", detail: err.message });
  }
});

// ===== Feature Flags (ADMIN)
async function getFlagsDoc() {
  return await AdminFlags.findOne({ _id: "flags" }) ||
         { _id: "flags", battleground:false, bonus:false, pvp:false, raffles:false, promos:true, updatedAt:new Date() };
}
app.get("/api/admin/flags/get", requireAdmin, async (_req, res) => {
  const f = await getFlagsDoc();
  res.json({ ok: true, flags: { battleground:f.battleground, bonus:f.bonus, pvp:f.pvp, raffles:f.raffles, promos:f.promos } });
});
app.post("/api/admin/flags/set", requireAdmin, async (req, res) => {
  const flags = req.body?.flags || {};
  const up = {
    battleground: !!flags.battleground,
    bonus: !!flags.bonus,
    pvp: !!flags.pvp,
    raffles: !!flags.raffles,
    promos: !!flags.promos,
    updatedAt: new Date()
  };
  await AdminFlags.updateOne({ _id: "flags" }, { $set: up }, { upsert: true });
  await AdminAudit.insertOne({ actor:req.user.username, evt:"flags.save", payload: up, createdAt:new Date() });
  res.json({ ok: true, flags: up });
});
app.post("/api/admin/flags/disable_all", requireAdmin, async (_req, res) => {
  const up = { battleground:false, bonus:false, pvp:false, raffles:false, promos:false, updatedAt:new Date() };
  await AdminFlags.updateOne({ _id: "flags" }, { $set: up }, { upsert: true });
  await AdminAudit.insertOne({ actor:req.user.username, evt:"flags.disable_all", createdAt:new Date() });
  res.json({ ok: true, flags: up });
});
app.post("/api/admin/flags/enable_all", requireAdmin, async (_req, res) => {
  const up = { battleground:true, bonus:true, pvp:true, raffles:true, promos:true, updatedAt:new Date() };
  await AdminFlags.updateOne({ _id: "flags" }, { $set: up }, { upsert: true });
  await AdminAudit.insertOne({ actor:req.user.username, evt:"flags.enable_all", createdAt:new Date() });
  res.json({ ok: true, flags: up });
});

// ===== Audit (ADMIN)
app.post("/api/admin/audit/track", requireAdmin, async (req, res) => {
  const { evt, payload } = req.body || {};
  await AdminAudit.insertOne({ actor: req.user.username, evt: String(evt||"custom"), payload: payload||null, createdAt: new Date() });
  res.json({ ok: true });
});
app.get("/api/admin/audit/list", requireAdmin, async (_req, res) => {
  const recs = await AdminAudit.find({}).sort({ createdAt: -1 }).limit(500).toArray();
  res.json({ ok: true, records: recs });
});
app.get("/api/admin/audit/export", requireAdmin, async (_req, res) => {
  const recs = await AdminAudit.find({}).sort({ createdAt: 1 }).toArray();
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="l3z_admin_audit_${Date.now()}.json"`);
  res.send(JSON.stringify(recs, null, 2));
});
app.post("/api/admin/audit/clear", requireAdmin, async (_req, res) => {
  const r = await AdminAudit.deleteMany({});
  res.json({ ok: true, n: r.deletedCount });
});

// ===== Bets
function computePotential(amount, picks = []) {
  const base = 1.5;
  const perPick = 0.1 * Math.max(0, (Array.isArray(picks) ? picks.length : 0) - 1);
  const mult = base + perPick;
  return Math.round(Number(amount || 0) * mult);
}

app.post("/api/bets/place", requireAuth, async (req, res) => {
  try {
    const { game, picks, amount } = req.body || {};
    const amt = n(amount);
    if (!game || !Array.isArray(picks) || !picks.length || !Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ error: "bad_input" });
    }

    const session = client.startSession();
    let betDoc = null, newBal = null;
    await session.withTransaction(async () => {
      const r = await Users.findOneAndUpdate(
        { _id: req.user._id, lbx: { $gte: amt } },
        { $inc: { lbx: -amt } },
        { returnDocument: "after", session }
      );
      if (!r.value) throw new Error("insufficient_funds");

      const potential = computePotential(amt, picks);
      const doc = {
        username: req.user.username,
        game: String(game),
        picks: picks.map(p => ({ label: String(p.label || p.choice || p.name || "Pick") })),
        amount: amt,
        potentialPayout: potential,
        status: "placed",
        createdAt: new Date(),
      };
      const ir = await Bets.insertOne(doc, { session });
      betDoc = { _id: ir.insertedId, ...doc };
      newBal = r.value.lbx;

      await LeaderEvents.insertOne({
        type: "bet_place", username: req.user.username, amount: amt, game: String(game), createdAt: new Date()
      }, { session });
    });
    await session.endSession();

    res.json({ ok: true, bet: betDoc, lbx: newBal });
  } catch (err) {
    if (String(err.message).includes("insufficient_funds")) {
      return res.status(400).json({ error: "insufficient_funds" });
    }
    res.status(500).json({ error: "place_failed", detail: err.message });
  }
});

app.get("/api/bets/my", requireAuth, async (req, res) => {
  const status = (req.query.status || "").toString().trim();
  const limit  = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
  const q = { username: req.user.username };
  if (["placed","settled","voided"].includes(status)) q.status = status;
  const bets = await Bets.find(q).sort({ createdAt: -1 }).limit(limit).toArray();
  res.json({ ok: true, bets });
});

app.get("/api/admin/bets/list", requireAdmin, async (req, res) => {
  const status = (req.query.status || "").toString().trim();
  const limit  = Math.min(500, Math.max(1, Number(req.query.limit || 100)));
  const term   = (req.query.q || "").toString().trim();

  const filter = {};
  if (["placed","settled","voided"].includes(status)) filter.status = status;
  if (term) {
    const rx = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    filter.$or = [
      { username: rx },
      { game: rx },
      { picks: { $elemMatch: { label: rx } } }
    ];
  }

  const bets = await Bets.find(filter).sort({ createdAt: -1 }).limit(limit).toArray();
  res.json({ ok: true, bets });
});

app.post("/api/admin/bets/settle", requireAdmin, async (req, res) => {
  try {
    const { betId, payout } = req.body || {};
    const amt = Math.max(0, n(payout));
    if (!betId || !Number.isFinite(amt)) return res.status(400).json({ error: "bad_input" });

    const session = client.startSession();
    let result = null;
    await session.withTransaction(async () => {
      const bet = await Bets.findOne({ _id: new ObjectId(betId) }, { session });
      if (!bet || bet.status !== "placed") throw new Error("bad_bet");
      if (amt > 0) await Users.updateOne({ username: bet.username }, { $inc: { lbx: amt } }, { session });
      const upd = await Bets.findOneAndUpdate(
        { _id: bet._id, status: "placed" },
        { $set: { status: "settled", payout: amt, settledAt: new Date() } },
        { returnDocument: "after", session }
      );
      result = upd.value;
      await LeaderEvents.insertOne({ type:"bet_settle", username: bet.username, payout: amt, game: bet.game, createdAt: new Date() }, { session });
      await AdminAudit.insertOne({ actor: req.user.username, evt:"bets.settle", payload:{ betId: bet._id.toString(), payout: amt }, createdAt:new Date() }, { session });
    });
    await session.endSession();

    if (!result) return res.status(409).json({ error: "already_settled_or_missing" });
    res.json({ ok: true, bet: result });
  } catch (err) {
    if (String(err.message).includes("bad_bet")) return res.status(400).json({ error: "bad_bet" });
    res.status(500).json({ error: "settle_failed", detail: err.message });
  }
});

app.post("/api/admin/bets/void", requireAdmin, async (req, res) => {
  try {
    const { betId, reason } = req.body || {};
    if (!betId) return res.status(400).json({ error: "bad_input" });

    const session = client.startSession();
    let result = null;
    await session.withTransaction(async () => {
      const bet = await Bets.findOne({ _id: new ObjectId(betId) }, { session });
      if (!bet || bet.status !== "placed") throw new Error("bad_bet");
      if (bet.amount > 0) await Users.updateOne({ username: bet.username }, { $inc: { lbx: bet.amount } }, { session });
      const upd = await Bets.findOneAndUpdate(
        { _id: bet._id, status: "placed" },
        { $set: { status: "voided", voidReason: reason || null, voidedAt: new Date() } },
        { returnDocument: "after", session }
      );
      result = upd.value;
      await LeaderEvents.insertOne({ type:"bet_void", username: bet.username, amount: bet.amount, game: bet.game, createdAt:new Date() }, { session });
      await AdminAudit.insertOne({ actor: req.user.username, evt:"bets.void", payload:{ betId: bet._id.toString(), reason: reason || null }, createdAt:new Date() }, { session });
    });
    await session.endSession();

    if (!result) return res.status(409).json({ error: "already_voided_or_missing" });
    res.json({ ok: true, bet: result });
  } catch (err) {
    if (String(err.message).includes("bad_bet")) return res.status(400).json({ error: "bad_bet" });
    res.status(500).json({ error: "void_failed", detail: err.message });
  }
});

app.post("/api/admin/bets/settle_bulk", requireAdmin, async (req, res) => {
  try {
    const decisions = Array.isArray(req.body?.decisions) ? req.body.decisions : [];
    if (!decisions.length) return res.status(400).json({ error: "bad_input" });

    let ok = 0, fail = 0;
    for (const d of decisions) {
      try {
        const payload = { betId: d.betId, payout: n(d.payout) };
        const session = client.startSession();
        await session.withTransaction(async () => {
          const bet = await Bets.findOne({ _id: new ObjectId(payload.betId) }, { session });
          if (!bet || bet.status !== "placed") throw new Error("bad_bet");
          const amt = Math.max(0, Number(payload.payout || 0));
          if (amt > 0) await Users.updateOne({ username: bet.username }, { $inc: { lbx: amt } }, { session });
          await Bets.updateOne({ _id: bet._id, status: "placed" }, { $set: { status:"settled", payout: amt, settledAt: new Date() } }, { session });
          await LeaderEvents.insertOne({ type:"bet_settle", username: bet.username, payout: amt, game: bet.game, createdAt:new Date() }, { session });
          await AdminAudit.insertOne({ actor: "bulk:"+req.user.username, evt:"bets.settle_bulk", payload:{ betId: bet._id.toString(), payout: amt }, createdAt:new Date() }, { session });
        });
        await session.endSession();
        ok++;
      } catch { fail++; }
    }
    res.json({ ok: true, settled: ok, failed: fail });
  } catch (err) {
    res.status(500).json({ error: "bulk_settle_failed", detail: err.message });
  }
});

// ===== Kick (stub integration)
app.get("/api/social/kick/status", requireAuth, async (req, res) => {
  const { kick } = (await Users.findOne({ _id: req.user._id }, { projection: { kick: 1 } })) || {};
  res.json({ ok: true, linked: !!kick?.linked, profile: kick?.profile || null });
});
app.post("/api/social/kick/link_start", requireAuth, async (_req, res) => {
  res.json({ ok: true, url: KICK_LINK_URL });
});
app.post("/api/social/kick/unlink", requireAuth, async (req, res) => {
  await Users.updateOne({ _id: req.user._id }, { $set: { kick: null } });
  res.json({ ok: true });
});

// ===== Static hosting (serve site files)
// Serve everything under repo root (assets/, pages/, admin/, etc.)
const STATIC_ROOT = process.env.STATIC_ROOT || __dirname;
app.use(express.static(STATIC_ROOT, {
  index: false, // we control "/" ourselves
  maxAge: NODE_ENV === "production" ? "1h" : 0,
  setHeaders(res, filePath) {
    // avoid caching HTML
    if (filePath.endsWith(".html")) res.setHeader("Cache-Control", "no-cache");
  },
}));

// Friendly landings
app.get("/", (_req, res) => res.redirect("/pages/profile.html"));
app.get("/admin", (_req, res) => res.redirect("/admin/login.html"));

// ===== Error handler (last)
app.use((err, _req, res, _next) => {
  const code = err.status || 500;
  res.status(code).json({ error: "server_error", detail: err.message || String(err) });
});

// ===== Start
app.listen(PORT, () => {
  console.log(`[L3Z] API listening on :${PORT} (${NODE_ENV}) — SameSite=${COOKIE_SAMESITE}, Secure=${COOKIE_SECURE}`);
});
