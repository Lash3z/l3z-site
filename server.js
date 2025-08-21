// /server.js — Single origin app server (static + API) for cPanel
import express from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import path from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app = express();

// Trust proxy (HTTPS on cPanel), needed for secure cookies
app.set("trust proxy", 1);

// Security headers (CSP via .htaccess is fine; disable here)
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// ===== Admin creds (env with safe defaults to YOUR values)
const ADMIN_USER = process.env.ADMIN_USER || "LASH3Z";
const ADMIN_PASS = process.env.ADMIN_PASS || "LASH3Z777";
process.env.ADMIN_USER = ADMIN_USER;
process.env.ADMIN_PASS = ADMIN_PASS;

// ===== Mount API routers (if a file is missing, we just skip it gracefully)
function mount(routerPath, mountPoint) {
  try {
    const r = require(routerPath);
    app.use(mountPoint, r.default ? r.default : r);
    console.log("Mounted", mountPoint, "→", routerPath);
  } catch (e) {
    console.warn("Skipped", mountPoint, "→", routerPath, "-", e.message);
  }
}

// Core feature routers
mount("./backend/routes/auth",        "/api/auth");
mount("./backend/routes/adminAuth",   "/api/admin/auth");
mount("./backend/routes/admin",       "/api/admin");
mount("./backend/routes/wallet",      "/api/wallet");
mount("./backend/routes/raffles",     "/api/raffles");
mount("./backend/routes/leaderboard", "/api/leaderboard");
mount("./backend/routes/lbx",         "/api/lbx");
mount("./backend/routes/pvp",         "/api/pvp");           // or battleground
mount("./backend/routes/battleground","/api/battleground");  // if you have it
mount("./backend/routes/bonushunt",   "/api/bonus-hunt");    // if you have it
mount("./backend/routes/jackpot",     "/api/jackpot");       // IMPORTANT for homepage widget
mount("./backend/routes/events",      "/api/events");
mount("./backend/routes/prizeclaims", "/api/prize-claims");

// Health check
app.get("/healthz", (req, res) => res.json({ ok: true }));

// ===== Static site (single origin) =====
const PUBLIC_DIR = __dirname; // your index.html/assets/pages live right here
app.use(express.static(PUBLIC_DIR, { extensions: ["html"], index: "index.html" }));

// Catch-all for pages BUT NOT API (don’t steal /api/*)
app.get(/^(?!\/api)(?!.*\.[a-zA-Z0-9]+$).*/, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`L3Z app listening on :${PORT}`));
