// backend/routes/auth.js
import express from "express";

const router = express.Router();

// Simple sanity route so the server starts even if you haven't wired real auth yet
router.post("/login", (req, res) => {
  // TODO: replace with real logic
  return res.json({ ok: true, user: req.body?.user ?? "guest" });
});

router.post("/logout", (req, res) => {
  return res.json({ ok: true });
});

export default router;
