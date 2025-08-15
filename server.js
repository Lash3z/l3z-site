// server.js — Render-safe boot + login intact
import fs from "fs/promises";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

// ----- ENV
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";

const ADMIN_USER   = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS   = process.env.ADMIN_PASS || "Lash3z777";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "supersecretkey";
const JWT_SECRET   = process.env.SECRET || ADMIN_SECRET;

const MONGO_URI = process.env.MONGO_URI || "";
const MONGO_DB  = process.env.MONGO_DB || "lash3z";

const ALLOW_MEMORY_FALLBACK = (process.env.ALLOW_MEMORY_FALLBACK || "true") === "true";

const JACKPOT_BASE_AUD     = Number(process.env.JACKPOT_BASE_AUD || 150);
const JACKPOT_PER_SUB_AUD  = Number(process.env.JACKPOT_PER_SUB_AUD || 2.5);
const JACKPOT_SUBS_CAP_AUD = Number(process.env.JACKPOT_SUBS_CAP_AUD || 100);

// ----- Paths
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// Allow override from env; otherwise ./public next to server.js
const PUBLIC_DIR = process.env.PUBLIC_DIR
  ? path.resolve(process.env.PUBLIC_DIR)
  : path.join(__dirname, "public");
const UP_DIR = path.join(__dirname, "uploads");

await fs.mkdir(UP_DIR, { recursive: true });

// Pre-check for SPA index so we don't crash on sendFile
let HAS_INDEX_HTML = false;
try {
  await fs.access(path.join(PUBLIC_DIR, "index.html"));
  HAS_INDEX_HTML = true;
} catch {
  console.warn(`[Server] No index.html at ${path.join(PUBLIC_DIR, "index.html")} — SPA fallback disabled.`);
}

// ----- DB (optional, with fast timeout so the app still boots)
let db = null;
if (MONGO_URI) {
  try {
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 8000 });
    await client.connect();
    db = client.db(MONGO_DB);
    console.log(`[DB] Connected to MongoDB: ${MONGO_DB}`);
  } catch (err) {
    console.error("[DB] Mongo connection failed:", err?.message || err);
    if (!ALLOW_MEMORY_FALLBACK) process.exit(1);
    console.warn("[DB] Using in-memory fallback.");
  }
} else if (!ALLOW_MEMORY_FALLBACK) {
  console.error("[DB] No MONGO_URI and memory fallback disabled. Exiting.");
  process.exit(1);
}

// ----- In-memory fallback store
const memoryStore = {
  giveaways: [],
  prizes: [],
  jackpot: { base: JACKPOT_BASE_AUD, perSub: JACKPOT_PER_SUB_AUD, subCap: JACKPOT_SUBS_CAP_AUD },
};

// ----- App
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());

// CORS only for /api
app.use("/api", (req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// JWT helpers
function generateAdminToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: "2h" });
}
function verifyAdminToken(req, res, next) {
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

// Admin auth
app.post(["/api/admin/gate/login", "/api/admin/login"], (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
  if (username.toLowerCase() === ADMIN_USER && password === ADMIN_PASS) {
    const token = generateAdminToken(username);
    res.cookie("admin_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 2,
      path: "/",
    });
    return res.json({ success: true });
  }
  return res.status(401).json({ error: "Invalid credentials" });
});
app.post(["/api/admin/gate/logout", "/api/admin/logout"], (req, res) => {
  res.clearCookie("admin_token", { path: "/" });
  res.json({ success: true });
});
app.get(["/api/admin/gate/check", "/api/admin/me"], verifyAdminToken, (req, res) => {
  res.json({ success: true, username: req.adminUser });
});

// Health + up endpoints (Render will hit these fine)
app.get("/api/health", (req, res) => {
  res.json({ ok: true, env: NODE_ENV, db: !!db, time: new Date().toISOString() });
});
app.get("/", (req, res) => {
  // If SPA present, let the fallback serve it; else show a simple up message
  if (HAS_INDEX_HTML) return res.redirect(302, "/app");
  res
    .status(200)
    .send("L3Z server is up. No SPA installed here. Set PUBLIC_DIR or add public/index.html.");
});
app.get("/app", (req, res, next) => {
  if (!HAS_INDEX_HTML) return res.status(404).send("No SPA found.");
  res.sendFile(path.join(PUBLIC_DIR, "index.html"), (err) => err && next(err));
});

// APIs (unchanged behavior)
app.get("/api/jackpot", async (req, res) => {
  if (db) {
    const settings = await db.collection("settings").findOne({ key: "jackpot" });
    return res.json(settings || memoryStore.jackpot);
  }
  return res.json(memoryStore.jackpot);
});
app.get("/api/giveaways", async (req, res) => {
  if (db) {
    const list = await db.collection("giveaways").find().toArray();
    return res.json(list);
  }
  return res.json(memoryStore.giveaways);
});
app.post("/api/prizes/claim", async (req, res) => {
  const { prizeId, user } = req.body || {};
  if (!prizeId || !user) return res.status(400).json({ error: "Missing data" });
  const claim = { prizeId, user, claimedAt: new Date() };
  if (db) await db.collection("claims").insertOne(claim);
  else memoryStore.prizes.push(claim);
  res.json({ success: true });
});

// Static files (safe if folder missing)
app.use(express.static(PUBLIC_DIR, {
  setHeaders(res, filePath) {
    if (/\.(png|jpe?g|gif|webp|svg|woff2?|mp3|mp4)$/i.test(filePath)) {
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    } else {
      res.setHeader("Cache-Control", "no-store");
    }
  }
}));

// SPA fallback only when present
app.get("*", (req, res, next) => {
  if (!HAS_INDEX_HTML) return res.status(404).send("Not found.");
  res.sendFile(path.join(PUBLIC_DIR, "index.html"), (err) => err && next(err));
});

// Error handler
app.use((err, req, res, next) => {
  console.error("[ERROR]", err?.stack || err);
  if (req.path.startsWith("/api")) return res.status(500).json({ error: "Server error" });
  res.status(500).send("Server error");
});

// Start
app.listen(PORT, HOST, () => {
  console.log(`[Server] http://${HOST}:${PORT} (${NODE_ENV})  PUBLIC_DIR=${PUBLIC_DIR}`);
});
