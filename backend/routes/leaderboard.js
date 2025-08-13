// backend/routes/leaderboard.js
import { Router } from "express";
import User from "../models/User.js";

const r = Router();

// quick health-check
r.get("/ping", (_req, res) => {
  res.json({ ok: true, api: "leaderboard", ts: new Date().toISOString() });
});

// GET /api/leaderboard
r.get("/", async (_req, res) => {
  try {
    const rows = await User.find({}, { username: 1, points: 1, _id: 0 })
      .sort({ points: -1 })
      .limit(100)
      .lean();

    const data = rows.map((u) => ({ player: u.username, points: u.points ?? 0 }));
    res.json(data);
  } catch (e) {
    console.error("[leaderboard] list failed:", e?.message);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default r;
