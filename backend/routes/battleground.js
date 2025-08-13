// backend/routes/battleground.js
import { Router } from "express";
import requireAdmin from "../middleware/auth.js";
import {
  getConfig, setConfig, openEvent, closeEvent, resetEvent,
  listPredictions, addPredictions
} from "../models/battleground/battleground.service.js";

const r = Router();

r.get("/ping", (_req, res) => res.json({ ok:true, api:"battleground", ts:new Date().toISOString() }));
r.get("/config", (_req, res) => res.json({ ok:true, config:getConfig() }));
r.get("/predictions", (req, res) => {
  const { eventId } = req.query || {};
  res.json({ ok:true, eventId: eventId || getConfig().currentEventId, predictions:listPredictions(eventId) });
});
r.post("/predict", (req, res) => {
  const out = addPredictions(req.body || {});
  res.status(out.ok ? 200 : 400).json(out);
});
r.post("/config", requireAdmin, (req, res) => res.json({ ok:true, config:setConfig(req.body || {}) }));
r.post("/open", requireAdmin, (req, res) => {
  const { eventId } = req.body || {};
  res.json(openEvent(eventId));
});
r.post("/close", requireAdmin, (_req, res) => res.json(closeEvent()));
r.post("/reset", requireAdmin, (req, res) => {
  const { eventId } = req.body || {};
  res.json(resetEvent(eventId));
});

export default r;
