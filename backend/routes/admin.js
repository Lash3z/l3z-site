// backend/routes/admin.js
import { Router } from "express";
import jwt from "jsonwebtoken";
import requireAdmin from "../middleware/auth.js";

const r = Router();
const SECRET = process.env.ADMIN_SECRET || process.env.SECRET || "change-me";
const isDev = () => process.env.NODE_ENV !== "production";

// Accept user/pass OR username/password/email (trim both sides)
r.post("/login", (req, res) => {
  const b = req.body || {};
  const user = String(b.user ?? b.username ?? b.email ?? "").trim();
  const pass = String(b.pass ?? b.password ?? "").trim();

  const envUser = String(process.env.ADMIN_USER || "").trim();
  const envPass = String(process.env.ADMIN_PASS || "").trim();

  if (isDev()) {
    console.log("[admin/login] got user='%s'(%d), passLen=%d", user, user.length, pass.length);
  }

  if (user === envUser && pass === envPass) {
    const token = jwt.sign({ role: "admin", sub: user }, SECRET, { expiresIn: "12h" });
    res.cookie("adminToken", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production" && !["127.0.0.1", "localhost"].includes(req.hostname),
      maxAge: 12 * 60 * 60 * 1000,
      path: "/",
    });
    return res.json({ ok: true });
  }

  if (isDev()) {
    console.warn("[admin/login] mismatch. envUser='%s'(%d) envPassLen=%d", envUser, envUser.length, envPass.length);
  }
  return res.status(401).json({ ok: false, error: "bad_credentials" });
});

r.post("/logout", (_req, res) => {
  res.clearCookie("adminToken", { path: "/" });
  res.json({ ok: true });
});

r.get("/me", requireAdmin, (_req, res) => res.json({ ok: true }));

export default r;
