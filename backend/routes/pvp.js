// backend/routes/pvp.js
import { Router } from "express";
import {
  getAllRounds, addRound, resetRounds,
  getConfig, setConfig, joinRound
} from "../models/pvp/pvp.service.js";
import requireAdmin from "../middleware/auth.js";

const r = Router();

r.get("/rounds", (_req, res) => res.json({ ok: true, rounds: getAllRounds() }));
r.get("/config", (_req, res) => res.json({ ok: true, config: getConfig() }));

r.post("/join", (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ ok: false, error: "missing_username" });
  const out = joinRound({ username });
  res.status(out.ok ? 200 : 400).json(out);
});

r.post("/rounds", requireAdmin, (req, res) => {
  const { id, leftGame, rightGame, entryFee } = req.body || {};
  if (!id || !leftGame || !rightGame) return res.status(400).json({ ok: false, error: "missing_fields" });
  const round = addRound({ id, leftGame, rightGame, entryFee });
  res.status(201).json({ ok: true, round });
});

r.delete("/rounds", requireAdmin, (_req, res) => { resetRounds(); res.json({ ok: true }); });
r.post("/config", requireAdmin, (req, res) => res.json({ ok:true, config:setConfig(req.body || {}) }));

export default r;
