// backend/middleware/auth.js
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

dotenv.config();

const ADMIN_SECRET = process.env.ADMIN_SECRET || process.env.SECRET || "";

export default function requireAdmin(req, res, next) {
  const bearer = (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
  const token = req.cookies?.adminToken || bearer;
  if (!token) return res.status(401).json({ ok: false, error: "unauthorized" });
  try {
    jwt.verify(token, ADMIN_SECRET);
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
}
