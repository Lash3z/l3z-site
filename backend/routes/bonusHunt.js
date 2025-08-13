import { Router } from "express";
import requireAdmin from "../middleware/auth.js";
import {
  getBonusHunts, addBonusHunt
} from "../models/bonushunt/bonushunt.service.js"; // <-- changed path & casing

const r = Router();

r.get("/", (_req, res) => {
  res.json({ ok: true, hunts: getBonusHunts() });
});

r.post("/", requireAdmin, (req, res) => {
  const { id, huntType, games = [] } = req.body || {};
  if (!id || !huntType) return res.status(400).json({ ok: false, error: "missing_fields" });
  const hunt = addBonusHunt({ id, huntType, games, createdAt: new Date().toISOString() });
  res.status(201).json({ ok: true, hunt });
});

export default r;
