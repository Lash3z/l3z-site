// backend/routes/adminAuth.js
import express from "express";
import jwt from "jsonwebtoken";

var router = express.Router();

function sameSiteNoneIfHttps(req) {
  // On Render you’re HTTPS; SameSite=None; Secure works for cross-origin admin UI if needed
  var isHttps = true;
  try {
    isHttps = (req.protocol === "https") || (req.headers["x-forwarded-proto"] === "https");
  } catch (e) {}
  return isHttps ? { sameSite: "none", secure: true } : { sameSite: "lax", secure: false };
}

router.post("/login", express.json(), function (req, res) {
  var u = (req.body && req.body.user) || "";
  var p = (req.body && req.body.pass) || "";
  var adminUser = process.env.ADMIN_USER || "";
  var adminPass = process.env.ADMIN_PASS || "";
  var secret = process.env.ADMIN_SECRET || process.env.SECRET || "";

  if (!secret) return res.status(500).json({ ok: false, error: "missing secret" });
  if (u !== adminUser || p !== adminPass) return res.status(401).json({ ok: false, error: "bad credentials" });

  var token = jwt.sign({ role: "admin", user: u }, secret, { algorithm: "HS256", expiresIn: "12h" });

  var cookieOpts = {
    httpOnly: true,
    path: "/",
    maxAge: 12 * 60 * 60 * 1000
  };
  var sameSiteSecure = sameSiteNoneIfHttps(req);
  cookieOpts.sameSite = sameSiteSecure.sameSite;
  cookieOpts.secure = sameSiteSecure.secure;

  res.cookie("adminToken", token, cookieOpts);
  res.json({ ok: true, token: token, user: u });
});

router.post("/logout", function (req, res) {
  res.clearCookie("adminToken", { path: "/" });
  res.json({ ok: true });
});

router.get("/session", function (req, res) {
  // lightweight check: do we have a valid cookie/bearer?
  var auth = (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
  var token = (req.cookies && req.cookies.adminToken) || auth;
  var secret = process.env.ADMIN_SECRET || process.env.SECRET || "";
  if (!token || !secret) return res.json({ isAdmin: false });

  try {
    var payload = jwt.verify(token, secret);
    res.json({ isAdmin: payload && payload.role === "admin", username: payload && payload.user });
  } catch (e) {
    res.json({ isAdmin: false });
  }
});

export default router;
