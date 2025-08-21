// /server.js — Single-origin: static site + API (cPanel / Passenger)
const express = require("express");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const path = require("path");

const app = express();

// Trust proxy (HTTPS behind Apache on cPanel)
app.set("trust proxy", 1);

// Security headers (CSP via .htaccess if you want; disabled here)
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// Admin creds (env first, fallback to your provided values)
process.env.ADMIN_USER = process.env.ADMIN_USER || "LASH3Z";
process.env.ADMIN_PASS = process.env.ADMIN_PASS || "LASH3Z777";

// Helper to mount routers safely
function mount(routerPath, mountPoint) {
  try {
    const r = require(routerPath);
    app.use(mountPoint, r.router ? r.router : (r.default ? r.default : r));
    console.log("Mounted", mountPoint, "->", routerPath);
  } catch (e) {
    console.warn("Skipped", mountPoint, "->", routerPath, "-", e.message);
  }
}

// ===== API Routes (adjust based on what exists in /backend/routes) =====
mount("./backend/routes/auth",        "/api/auth");
mount("./backend/routes/adminAuth",   "/api/admin/auth");
mount("./backend/routes/admin",       "/api/admin");
mount("./backend/routes/wallet",      "/api/wallet");
mount("./backend/routes/raffles",     "/api/raffles");
mount("./backend/routes/leaderboard", "/api/leaderboard");
mount("./backend/routes/lbx",         "/api/lbx");
mount("./backend/routes/pvp",         "/api/pvp");
mount("./backend/routes/battleground","/api/battleground");
mount("./backend/routes/bonushunt",   "/api/bonus-hunt");
mount("./backend/routes/jackpot",     "/api/jackpot");  // IMPORTANT for homepage widget
mount("./backend/routes/events",      "/api/events");
mount("./backend/routes/prizeclaims", "/api/prize-claims");

// Health
app.get("/api/healthz", (req, res) => res.json({ ok: true }));

// ===== Static site =====
const PUBLIC_DIR = __dirname; // index.html, /assets, /pages live here
app.use(express.static(PUBLIC_DIR, { extensions: ["html"], index: "index.html" }));

// Catch-all for pages BUT NOT /api/*
app.get(/^(?!\/api)(?!.*\.[a-zA-Z0-9]+$).*/, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`L3Z app listening on :${PORT}`));
