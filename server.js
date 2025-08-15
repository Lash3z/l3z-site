import fs from "fs/promises";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";

// --- Load env file
dotenv.config();

// --- Constants from ENV
const HOST = process.env.HOST || "0.0.0.0";
const PORT = parseInt(process.env.PORT, 10) || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";

const ADMIN_USER   = (process.env.ADMIN_USER || "lash3z").toLowerCase();
const ADMIN_PASS   = process.env.ADMIN_PASS || "Lash3z777";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "supersecretkey";
const JWT_SECRET   = process.env.SECRET || ADMIN_SECRET;

const MONGO_URI = process.env.MONGO_URI;
const MONGO_DB  = process.env.MONGO_DB;

const ALLOW_MEMORY_FALLBACK = process.env.ALLOW_MEMORY_FALLBACK === "true";

const JACKPOT_BASE_AUD      = parseFloat(process.env.JACKPOT_BASE_AUD || "150");
const JACKPOT_PER_SUB_AUD   = parseFloat(process.env.JACKPOT_PER_SUB_AUD || "2.5");
const JACKPOT_SUBS_CAP_AUD  = parseFloat(process.env.JACKPOT_SUBS_CAP_AUD || "100");

const SIGNUP_BONUS   = parseInt(process.env.SIGNUP_BONUS || "50", 10);
const WALLET_CURRENCY = process.env.WALLET_CURRENCY || "L3Z";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UP_DIR = path.join(__dirname, "uploads");

// --- Ensure uploads dir exists
await fs.mkdir(UP_DIR, { recursive: true });

// --- Mongo connection (optional)
let db = null;
if (MONGO_URI) {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    db = client.db(MONGO_DB);
    console.log(`[DB] Connected to MongoDB: ${MONGO_DB}`);
  } catch (err) {
    console.error("[DB] Mongo connection failed:", err);
    if (!ALLOW_MEMORY_FALLBACK) process.exit(1);
  }
} else if (!ALLOW_MEMORY_FALLBACK) {
  console.error("[DB] No Mongo URI and memory fallback not allowed. Exiting.");
  process.exit(1);
}

// --- Memory fallback DB
const memoryStore = {
  giveaways: [],
  prizes: [],
  jackpot: { base: JACKPOT_BASE_AUD, perSub: JACKPOT_PER_SUB_AUD, subCap: JACKPOT_SUBS_CAP_AUD }
};

// --- Express setup
const app = express();
app.use(express.json());
app.use(cookieParser());

// --- CORS middleware
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// --- JWT helper
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
    res.status(401).json({ error: "Unauthorized" });
  }
}

// --- Admin login/logout/check (single handlers for both routes)
function adminLoginHandler(req, res) {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
  if (username.toLowerCase() === ADMIN_USER && password === ADMIN_PASS) {
    const token = generateAdminToken(username);
    res.cookie("admin_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: NODE_ENV === "production"
    });
    return res.json({ success: true });
  }
  res.status(401).json({ error: "Invalid credentials" });
}

function adminLogoutHandler(req, res) {
  res.clearCookie("admin_token");
  res.json({ success: true });
}

function adminCheckHandler(req, res) {
  res.json({ success: true, username: req.adminUser });
}

app.post(["/api/admin/gate/login", "/api/admin/login"], adminLoginHandler);
app.post(["/api/admin/gate/logout", "/api/admin/logout"], adminLogoutHandler);
app.get(["/api/admin/gate/check", "/api/admin/me"], verifyAdminToken, adminCheckHandler);

// --- Jackpot API
app.get("/api/jackpot", async (req, res) => {
  if (db) {
    const settings = await db.collection("settings").findOne({ key: "jackpot" });
    return res.json(settings || memoryStore.jackpot);
  }
  res.json(memoryStore.jackpot);
});

// --- Giveaways API (simplified)
app.get("/api/giveaways", async (req, res) => {
  if (db) {
    const list = await db.collection("giveaways").find().toArray();
    return res.json(list);
  }
  res.json(memoryStore.giveaways);
});

// --- Prize claim API
app.post("/api/prizes/claim", async (req, res) => {
  const { prizeId, user } = req.body;
  if (!prizeId || !user) return res.status(400).json({ error: "Missing data" });

  const claim = { prizeId, user, claimedAt: new Date() };
  if (db) {
    await db.collection("claims").insertOne(claim);
  } else {
    memoryStore.prizes.push(claim);
  }
  res.json({ success: true });
});

// --- Static file serving
app.use(express.static(path.join(__dirname, "public"), {
  setHeaders(res, filePath) {
    if (/\.(png|jpe?g|gif|webp|svg|woff2?|mp3|mp4)$/i.test(filePath)) {
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    }
  }
}));

// --- Fallback to index.html for SPA
app.get("*", async (req, res, next) => {
  const filePath = path.join(__dirname, "public", "index.html");
  try {
    const html = await fs.readFile(filePath, "utf8");
    res.send(html);
  } catch (err) {
    next();
  }
});

// --- Start server
app.listen(PORT, HOST, () => {
  console.log(`[Server] Running at http://${HOST}:${PORT} in ${NODE_ENV} mode`);
});
