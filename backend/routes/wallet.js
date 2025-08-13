// backend/routes/wallet.js — compatibility version (ESM)
import { Router } from "express";
import { getBalance, getLedger, credit, debit, adjust } from "../models/wallet/wallet.service.js";

const r = Router();
const num = v => Number.isFinite(Number(v)) ? Number(v) : NaN;
const str = (v, d="") => (typeof v === "string" && v.trim()) ? v.trim() : d;

// GET /api/wallet/me?viewer=<username>
r.get("/me", async (req, res) => {
  const viewer = str(req.query.viewer) || str(req.headers["x-viewer-name"]);
  if (!viewer) return res.status(400).json({ ok:false, error:"missing_viewer" });
  const out = await getBalance(viewer.toLowerCase());
  res.json({ ok:true, user: viewer, balance: out.balance });
});

// GET /api/wallet/credit?username=&amount=&reason=
r.get("/credit", async (req, res) => {
  const username = str(req.query.username);
  const amount = num(req.query.amount);
  const reason = str(req.query.reason, "credit");
  if (!username || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ ok:false, error:"bad_input" });
  const out = await credit(username.toLowerCase(), amount, reason);
  res.json(out);
});

// POST /api/wallet/credit { username, amount, reason? }
r.post("/credit", async (req, res) => {
  const username = str(req.body?.username);
  const amount = num(req.body?.amount);
  const reason = str(req.body?.reason, "credit");
  if (!username || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ ok:false, error:"bad_input" });
  const out = await credit(username.toLowerCase(), amount, reason);
  res.json(out);
});

// POST /api/wallet/adjust { username, delta, reason? }
r.post("/adjust", async (req, res) => {
  const username = str(req.body?.username);
  const delta = num(req.body?.delta);
  const reason = str(req.body?.reason, "adjust");
  if (!username || !Number.isFinite(delta) || delta === 0) return res.status(400).json({ ok:false, error:"bad_input" });
  const out = await adjust(username.toLowerCase(), delta, reason);
  res.json(out);
});

// POST /api/wallet/me/spend { amount, reason? } (viewer via header or ?viewer=)
r.post("/me/spend", async (req, res) => {
  const viewer = str(req.query.viewer) || str(req.headers["x-viewer-name"]);
  const amount = num(req.body?.amount);
  const reason = str(req.body?.reason, "spend");
  if (!viewer || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ ok:false, error:"bad_input" });
  const out = await debit(viewer.toLowerCase(), amount, reason);
  res.json(out);
});

// GET /api/wallet/ledger/:username?limit=50
r.get("/ledger/:username", async (req, res) => {
  const limit = Number.isFinite(Number(req.query.limit)) ? Number(req.query.limit) : 50;
  const out = await getLedger(req.params.username.toLowerCase(), limit);
  res.json(out);
});

// KEEP THIS LAST so it doesn't catch the routes above
// GET /api/wallet/:username
r.get("/:username", async (req, res) => {
  const out = await getBalance(req.params.username.toLowerCase());
  res.json(out);
});

export default r;
