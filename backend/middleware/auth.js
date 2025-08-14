// backend/middleware/auth.js
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

dotenv.config();

var secretsRaw = [
  process.env.ADMIN_SECRET,
  process.env.SECRET
].filter(function (x) { return !!x; });
var SECRETS = Array.from(new Set(secretsRaw)); // dedupe

function parseCookieHeader(header) {
  header = header || "";
  var out = {};
  header.split(";").forEach(function (part) {
    part = (part || "").trim();
    if (!part) return;
    var idx = part.indexOf("=");
    if (idx === -1) { out[decodeURIComponent(part)] = ""; return; }
    var k = decodeURIComponent(part.slice(0, idx));
    var v = decodeURIComponent(part.slice(idx + 1));
    out[k] = v;
  });
  return out;
}

function getToken(req) {
  var auth = (req.headers && req.headers.authorization) || "";
  if (/^Bearer\s+/i.test(auth)) {
    return auth.replace(/^Bearer\s+/i, "").trim();
  }
  if (req.cookies && (req.cookies.adminToken || req.cookies.token)) {
    return req.cookies.adminToken || req.cookies.token;
  }
  var cookies = parseCookieHeader((req.headers && req.headers.cookie) || "");
  if (cookies.adminToken) return cookies.adminToken;
  if (cookies.token) return cookies.token;
  if (req.query && req.query.token) return String(req.query.token);
  return "";
}

export default function requireAdmin(req, res, next) {
  if (!SECRETS.length) {
    return res.status(500).json({ ok: false, error: "admin auth misconfigured: missing ADMIN_SECRET/SECRET" });
  }
  var token = getToken(req);
  if (!token) return res.status(401).json({ ok: false, error: "unauthorized" });

  for (var i = 0; i < SECRETS.length; i++) {
    try {
      var payload = jwt.verify(token, SECRETS[i]); // HS256 default
      req.admin = payload;
      return next();
    } catch (e) {
      // try next secret
    }
  }
  return res.status(401).json({ ok: false, error: "unauthorized" });
}
