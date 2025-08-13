// server.js (ESM, single clean file)
import express from "express";
import path from "path";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";
import mongoose from "mongoose";
import compression from "compression";
import crypto from "crypto";
import fs from "fs/promises";
import { fileURLToPath } from "url";

import vipAwardsRouter from "./backend/routes/vipAwards.js";
import rafflesRouter from "./backend/routes/raffles.js";
import battlegroundRouter from "./backend/routes/battleground.js";
import pvpRouter from "./backend/routes/pvp.js";
import adminRouter from "./backend/routes/admin.js";
// LBX deposits/wallet routes
import lbxRouter from "./backend/routes/lbx.js";
import walletRouter from "./backend/routes/wallet.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";

// Public API base for client (blank = same-origin)
const PUBLIC_API_BASE = process.env.PUBLIC_API_BASE || "";

/* ------------------------------------
 * Core middleware
 * ------------------------------------ */
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(compression());

// CORS
const ALLOW = new Set([
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5173",
  "https://lash3z.com",
  "https://www.lash3z.com",
]);
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || ALLOW.has(origin)) return cb(null, true);
      return cb(null, true); // allow all in dev
    },
    credentials: true,
  })
);

/* ------------------------------------
 * Mongo
 * ------------------------------------ */
const MONGO_URI = process.env.MONGO_URI;
if (MONGO_URI) {
  mongoose.set("strictQuery", true);
  mongoose
    .connect(MONGO_URI, { dbName: process.env.MONGO_DB || undefined })
    .then(() => console.log("[mongo] connected"))
    .catch((err) => console.error("[mongo] failed:", err?.message || err));
} else {
  console.warn("[mongo] MONGO_URI not set — continuing without DB");
}
const mongoUp = () => mongoose?.connection?.readyState === 1;

/* ------------------------------------
 * Optional simple models (slot wheel / raffle entries)
 * ------------------------------------ */
let SlotwheelEntry, RaffleEntry;
try {
  const slotwheelSchema = new mongoose.Schema(
    { gid: { type: String, index: true }, user: { type: String, index: true }, ts: { type: Date, default: () => new Date() } },
    { versionKey: false }
  );
  slotwheelSchema.index({ gid: 1, user: 1 }, { unique: true });
  SlotwheelEntry = mongoose.models.SlotwheelEntry || mongoose.model("SlotwheelEntry", slotwheelSchema);

  const raffleSchema = new mongoose.Schema(
    { rid: { type: String, index: true }, user: { type: String, index: true }, ts: { type: Date, default: () => new Date() } },
    { versionKey: false }
  );
  raffleSchema.index({ rid: 1, user: 1 }, { unique: true });
  RaffleEntry = mongoose.models.RaffleEntry || mongoose.model("RaffleEntry", raffleSchema);
} catch {
  /* ignore if mongo not ready */
}

/* ------------------------------------
 * Admin Gate (server-side, 6h cookie)
 * ------------------------------------ */
const ADMIN_USER = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS = process.env.ADMIN_PASS || "Lash3z777";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "change-me-now";
const ADMIN_COOKIE = "adm_sess";
const ADMIN_MAX_AGE_MS = 6 * 60 * 60 * 1000; // 6 hours

function signToken(payloadObj) {
  const body = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = crypto.createHmac("sha256", ADMIN_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function verifyToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const expect = crypto.createHmac("sha256", ADMIN_SECRET).update(body).digest("base64url");
  if (sig !== expect) return null;
  try {
    const obj = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!obj || Date.now() > Number(obj.exp || 0)) return null;
    return obj;
  } catch {
    return null;
  }
}
function setAdminCookie(res, username) {
  const payload = { u: String(username), exp: Date.now() + ADMIN_MAX_AGE_MS };
  const token = signToken(payload);
  res.cookie(ADMIN_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: ADMIN_MAX_AGE_MS,
    path: "/",
  });
}
function clearAdminCookie(res) {
  res.clearCookie(ADMIN_COOKIE, { path: "/" });
}
function adminGuard(req, res, next) {
  const tok = req.cookies?.[ADMIN_COOKIE];
  const ok = verifyToken(tok);
  if (ok) return next();

  if (req.accepts("html")) {
    return res
      .status(401)
      .type("html")
      .send(
        `<!doctype html><meta charset="utf-8">
         <title>Admin Locked</title>
         <style>body{background:#0b0f10;color:#eaf7ff;font-family:Segoe UI,system-ui,Arial,sans-serif;padding:32px}</style>
         <h1>Administration Locked</h1>
         <p>You must unlock admin on the <a href="/index.html">Dashboard</a> first.</p>`
      );
  }
  return res.status(401).json({ ok: false, error: "admin_locked" });
}

// Admin gate endpoints
app.post("/api/admin/gate/login", (req, res) => {
  const u = String(req.body?.username || "").trim().toLowerCase();
  const p = String(req.body?.password || "");
  if (u === ADMIN_USER && p === ADMIN_PASS) {
    setAdminCookie(res, u);
    return res.json({ ok: true, admin: true, exp: Date.now() + ADMIN_MAX_AGE_MS });
  }
  return res.status(401).json({ ok: false, error: "bad_credentials" });
});
app.post("/api/admin/gate/logout", (_req, res) => {
  clearAdminCookie(res);
  res.json({ ok: true });
});
app.get("/api/admin/gate/check", (req, res) => {
  const ok = verifyToken(req.cookies?.[ADMIN_COOKIE]);
  res.json({ ok: true, admin: !!ok, exp: ok?.exp || 0, user: ok?.u || null });
});

/* ------------------------------------
 * JACKPOT API  (AUD floor + subs cap + monthly rollover)
 * ------------------------------------ */
const JACKPOT_BASE_AUD   = Number(process.env.JACKPOT_BASE_AUD || 150);
const SUBS_CAP_AUD       = Number(process.env.JACKPOT_SUBS_CAP_AUD || 100);
const SUB_VALUE_AUD      = Number(process.env.JACKPOT_PER_SUB_AUD || 2.5);
const DATA_DIR           = path.resolve(__dirname, "data");
const JACKPOT_FILE       = path.join(DATA_DIR, "jackpot.json");

// Melbourne helpers
function melNow(){ return new Date(new Date().toLocaleString("en-AU",{ timeZone:"Australia/Melbourne" })); }
function melMonthKey(d=melNow()){ return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}`; }
function melNextMonthStartTs(){
  const d = melNow();
  const y = d.getFullYear();
  const m = d.getMonth();
  const nextY = m===11 ? y+1 : y;
  const nextM = m===11 ? 1   : (m+2);
  return Date.parse(`${nextY}-${String(nextM).padStart(2,"0")}-01T00:00:00+10:00`);
}

async function ensureDir(p){ try{ await fs.mkdir(p,{recursive:true}); }catch{} }
async function loadJackpot(){
  await ensureDir(DATA_DIR);
  try{
    const raw = await fs.readFile(JACKPOT_FILE,"utf8");
    const obj = JSON.parse(raw);
    if(typeof obj.subsCents!=="number") obj.subsCents = 0;
    if(typeof obj.manualCents!=="number") obj.manualCents = 0;
    if(typeof obj.month!=="string") obj.month = melMonthKey();
    return obj;
  }catch{
    const seed = { month: melMonthKey(), subsCents: 0, manualCents: 0 };
    await fs.writeFile(JACKPOT_FILE, JSON.stringify(seed,null,2));
    return seed;
  }
}
async function saveJackpot(state){
  await ensureDir(DATA_DIR);
  await fs.writeFile(JACKPOT_FILE, JSON.stringify(state,null,2));
}
function computeAmountAUD(state){
  const subsAud = Math.min(state.subsCents/100, SUBS_CAP_AUD);
  const manualAud = state.manualCents/100;
  return JACKPOT_BASE_AUD + subsAud + manualAud;
}
async function rolloverIfNeeded(state){
  const keyNow = melMonthKey();
  if(state.month !== keyNow){
    state.month = keyNow;
    state.subsCents = 0;
    state.manualCents = 0;
    await saveJackpot(state);
  }
  return state;
}

// GET current jackpot (public)
app.get("/api/jackpot", async (_req,res)=>{
  const st = await rolloverIfNeeded(await loadJackpot());
  res.json({
    ok:true,
    currency:"AUD",
    month: st.month,
    base: JACKPOT_BASE_AUD,
    subsCap: SUBS_CAP_AUD,
    amount: Number(computeAmountAUD(st).toFixed(2)),
    nextResetTs: melNextMonthStartTs()
  });
});

// Admin endpoints (require admin cookie)
app.post("/api/jackpot/add-subs", adminGuard, async (req,res)=>{
  const count = Math.max(0, Math.floor(Number(req.body?.count||0)));
  const st = await rolloverIfNeeded(await loadJackpot());
  if(count>0){
    st.subsCents += Math.round(count * SUB_VALUE_AUD * 100);
    await saveJackpot(st);
  }
  res.json({ ok:true, amount: Number(computeAmountAUD(st).toFixed(2)) });
});
app.post("/api/jackpot/adjust", adminGuard, async (req,res)=>{
  const delta = Number(req.body?.delta||0); // +/- AUD
  const st = await rolloverIfNeeded(await loadJackpot());
  st.manualCents = Math.max(0, st.manualCents + Math.round(delta*100));
  await saveJackpot(st);
  res.json({ ok:true, amount: Number(computeAmountAUD(st).toFixed(2)) });
});
app.post("/api/jackpot/set", adminGuard, async (req,res)=>{
  const target = Math.max(0, Number(req.body?.amount||0));
  const st = await rolloverIfNeeded(await loadJackpot());
  const current = computeAmountAUD(st);
  const delta = Math.round((target - current)*100);
  st.manualCents = Math.max(0, st.manualCents + delta);
  await saveJackpot(st);
  res.json({ ok:true, amount: Number(computeAmountAUD(st).toFixed(2)) });
});
app.post("/api/jackpot/reset", adminGuard, async (_req,res)=>{
  const st = await loadJackpot();
  st.month = melMonthKey();
  st.subsCents = 0;
  st.manualCents = 0;
  await saveJackpot(st);
  res.json({ ok:true, amount: Number(computeAmountAUD(st).toFixed(2)) });
});

/* ------------------------------------
 * API routes (rest)
 * ------------------------------------ */
app.use("/api/admin", adminRouter);
app.use("/api/vip-awards", vipAwardsRouter);
app.use("/api/battleground", battlegroundRouter);
app.use("/api/pvp", pvpRouter);
app.use("/api", lbxRouter);
app.use("/api/raffles", rafflesRouter);
app.use("/api/wallet", walletRouter);

// Simple slot wheel entries
app.get("/api/giveaways/slotwheel/:id/entries", async (req, res) => {
  const gid = String(req.params.id || "").trim();
  if (!gid) return res.status(400).json({ ok: false, error: "bad_id" });
  if (mongoUp() && SlotwheelEntry) {
    const rows = await SlotwheelEntry.find({ gid }).sort({ ts: 1 }).lean();
    return res.json({ ok: true, entries: rows.map((r) => ({ user: r.user, ts: r.ts })) });
  }
  return res.json({ ok: true, entries: [] });
});
app.post("/api/giveaways/slotwheel/:id/entries", async (req, res) => {
  const gid = String(req.params.id || "").trim();
  const user = String((req.body?.user || "").toUpperCase());
  if (!gid || !user) return res.status(400).json({ ok: false, error: "bad_input" });
  if (mongoUp() && SlotwheelEntry) {
    try {
      await SlotwheelEntry.updateOne(
        { gid, user },
        { $setOnInsert: { gid, user }, $set: { ts: new Date() } },
        { upsert: true }
      );
      return res.json({ ok: true });
    } catch (e) {
      if (e?.code === 11000) return res.json({ ok: true, already: true });
      return res.status(500).json({ ok: false, error: e?.message || "db_error" });
    }
  }
  return res.json({ ok: true });
});

// Simple raffle entries (base endpoints)
app.get("/api/raffles/:id/entries", async (req, res) => {
  const rid = String(req.params.id || "").trim();
  if (!rid) return res.status(400).json({ ok: false, error: "bad_id" });
  if (mongoUp() && RaffleEntry) {
    const rows = await RaffleEntry.find({ rid }).sort({ ts: 1 }).lean();
    return res.json({ ok: true, entries: rows.map((r) => ({ user: r.user, ts: r.ts })) });
  }
  return res.json({ ok: true, entries: [] });
});
app.post("/api/raffles/:id/entries", async (req, res) => {
  const rid = String(req.params.id || "").trim();
  const user = String((req.body?.user || "").toUpperCase());
  if (!rid || !user) return res.status(400).json({ ok: false, error: "bad_input" });
  if (mongoUp() && RaffleEntry) {
    try {
      await RaffleEntry.updateOne(
        { rid, user },
        { $setOnInsert: { rid, user }, $set: { ts: new Date() } },
        { upsert: true }
      );
      return res.json({ ok: true });
    } catch (e) {
      if (e?.code === 11000) return res.json({ ok: true, already: true });
      return res.status(500).json({ ok: false, error: e?.message || "db_error" });
    }
  }
  return res.json({ ok: true });
});

// Health
app.get("/healthz", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

/* ------------------------------------
 * Static files (protect admin pages) + HTML injector
 * ------------------------------------ */
const ROOT_DIR = __dirname;
const assetsDir = path.resolve(__dirname, "assets");
const pagesDir  = path.resolve(__dirname, "pages");
const adminDir  = path.resolve(__dirname, "admin");
const indexHtml = path.resolve(__dirname, "index.html");

// Guard only admin pages
app.use("/pages/dashboard/admin", adminGuard);

// HTML injector (adds API_BASE + api-base.js into every HTML)
async function sendInjectedHtml(filePath, res, next) {
  try {
    let html = await fs.readFile(filePath, "utf8");

    // Avoid double-injecting if already present
    const already = html.includes("/assets/api-base.js") || html.includes("window.API_BASE");
    if (!already) {
      const inject =
        `\n<script>window.API_BASE=${JSON.stringify(PUBLIC_API_BASE)};</script>\n` +
        `<script src="/assets/api-base.js"></script>\n`;
      if (/<\/head>/i.test(html)) {
        html = html.replace(/<\/head>/i, inject + "</head>");
      } else if (/<\/body>/i.test(html)) {
        html = html.replace(/<\/body>/i, inject + "</body>");
      } else {
        html = inject + html;
      }
    }
    res.type("html").send(html);
  } catch (err) {
    next(err);
  }
}

// Serve "/" and "/index.html" with injection
app.get(["/","/index.html"], (req,res,next) => {
  sendInjectedHtml(indexHtml, res, next);
});

// Serve any other .html file with injection
app.get(/.*\.html$/i, async (req,res,next) => {
  const file = path.join(ROOT_DIR, req.path);
  sendInjectedHtml(file, res, err => {
    if (err) next(); // fall through to static if not found
  });
});

// Static
app.use(
  express.static(ROOT_DIR, {
    index: false,
    extensions: ["html"],
    setHeaders(res, filePath) {
      if (/\.(png|jpe?g|gif|webp|svg|css|js|woff2?|mp3|mp4)$/i.test(filePath)) {
        res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
      } else {
        res.setHeader("Cache-Control", "no-cache");
      }
    },
  })
);
app.use("/assets", express.static(assetsDir, { fallthrough: true }));
app.use("/pages",  express.static(pagesDir,  { fallthrough: true }));
app.use("/admin",  express.static(adminDir,  { fallthrough: true }));

// Redirect old path to root
app.get(
  ["/pages/dashboard/home", "/pages/dashboard/home/", "/pages/dashboard/home/index.html"],
  (_req, res) => res.redirect(302, "/index.html")
);

// Health HTML
app.get("/health.html", (_req, res) => res.sendFile(path.resolve(__dirname, "health.html")));

// Favicon
app.get("/favicon.ico", (_req, res) => {
  res.sendFile(path.resolve(__dirname, "assets", "L3Z_logoMain.png"));
});

/* ------------------------------------
 * 404 handler (HTML for pages, JSON for API)
 * ------------------------------------ */
app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ ok: false, error: "not_found" });
  }
  res
    .status(404)
    .type("html")
    .send(
      `<!doctype html><meta charset="utf-8">
       <title>404</title>
       <style>body{background:#0b0f10;color:#eaf7ff;font-family:Segoe UI,system-ui,Arial,sans-serif;padding:32px}</style>
       <h1>Not Found</h1>
       <p>The path <code>${req.originalUrl}</code> doesn’t exist.</p>
       <p><a href="/index.html">Back to Home</a></p>`
    );
});

/* ------------------------------------
 * Boot
 * ------------------------------------ */
process.on("unhandledRejection", e => console.error("[unhandledRejection]", e));
process.on("uncaughtException", e => console.error("[uncaughtException]", e));

app.listen(PORT, HOST, () => {
  console.log(`Server running: http://${HOST}:${PORT}`);
});

