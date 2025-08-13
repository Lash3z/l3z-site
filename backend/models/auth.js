// backend/routes/auth.js
import { Router } from "express";
import bcrypt from "bcryptjs";
import User from "../models/User.js";
import { signViewerToken, requireViewer } from "../middleware/viewerAuth.js";

const r = Router();
const isProd = (process.env.NODE_ENV || "").toLowerCase() === "production";
const SIGNUP_BONUS = Number(process.env.SIGNUP_BONUS ?? 50);

function viewerCookie(res, token) {
  res.cookie("viewerToken", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

// POST /api/auth/register { username, password }
r.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ ok: false, error: "missing_fields" });

    const uLower = String(username).toLowerCase().trim();
    const existing = await User.findOne({ username: uLower });
    if (existing) return res.status(409).json({ ok: false, error: "username_taken" });

    const passwordHash = await bcrypt.hash(password, 12);
    const u = new User({ username: uLower, passwordHash, balance: Math.max(0, SIGNUP_BONUS) });

    if (SIGNUP_BONUS > 0) {
      u.ledger.push({ delta: SIGNUP_BONUS, reason: "signup bonus", ref: `signup_${Date.now()}` });
    }

    await u.save();

    const token = signViewerToken({ id: u._id.toString(), username: u.username });
    viewerCookie(res, token);

    res.status(201).json({ ok: true, user: { username: u.username, balance: u.balance, currency: u.currency } });
  } catch (e) {
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// POST /api/auth/login { username, password }
r.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ ok: false, error: "missing_fields" });

    const u = await User.findOne({ username: String(username).toLowerCase().trim() });
    if (!u) return res.status(401).json({ ok: false, error: "bad_credentials" });

    const ok = await bcrypt.compare(password, u.passwordHash);
    if (!ok) return res.status(401).json({ ok: false, error: "bad_credentials" });

    const token = signViewerToken({ id: u._id.toString(), username: u.username });
    viewerCookie(res, token);

    res.json({ ok: true, user: { username: u.username, balance: u.balance, currency: u.currency } });
  } catch {
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// GET /api/auth/me
r.get("/me", requireViewer, async (req, res) => {
  const u = await User.findOne({ _id: req.viewer.id }).lean();
  if (!u) return res.status(404).json({ ok: false, error: "not_found" });
  res.json({ ok: true, user: { username: u.username, balance: u.balance, currency: u.currency } });
});

// POST /api/auth/logout
r.post("/logout", (_req, res) => {
  res.clearCookie("viewerToken", { httpOnly: true, sameSite: "lax", secure: isProd });
  res.sendStatus(204);
});

export default r;
