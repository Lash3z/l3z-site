// /config/security.js
import jwt from "jsonwebtoken";
import { CFG } from "./env.js";

export function adminCookieOptions() {
  const isProd = CFG.NODE_ENV === "production";
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd,
    maxAge: 2 * 60 * 60 * 1000 // 2h
  };
}

export function signAdmin(payload = { role: "admin" }) {
  if (!CFG.ADMIN_SECRET) throw new Error("ADMIN_SECRET not set");
  return jwt.sign(payload, CFG.ADMIN_SECRET, { expiresIn: "2h" });
}

export function verifyAdmin(token = "") {
  if (!CFG.ADMIN_SECRET) return null;
  try {
    return jwt.verify(token, CFG.ADMIN_SECRET);
  } catch {
    return null;
  }
}
