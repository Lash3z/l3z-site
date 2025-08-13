// backend/routes/jackpot.js
import { Router } from "express";
import Jackpot from "../models/jackpot.model.js";
import requireAdmin from "../middleware/auth.js";

const r = Router();

/* ---------- time helpers ---------- */
function monthContext(d = new Date()) {
  const y = d.getFullYear();
  const m = d.getMonth(); // 0..11
  const start = new Date(y, m, 1, 0, 0, 0, 0);
  const next = new Date(y, m + 1, 1, 0, 0, 0, 0);
  const end = new Date(next.getTime() - 1);
  const key = `${y}-${String(m + 1).padStart(2, "0")}`;
  return { key, start, end, now: d };
}

async function getOrCreate(monthKey) {
  let doc = await Jackpot.findOne({ monthKey });
  if (!doc) doc = await Jackpot.create({ monthKey, extra: 0 });
  return doc;
}

// Compute base (0..150) since (overrideStartISO || month start), + extra
function computeValue(doc, ctx) {
  const start = doc.overrideStartISO && doc.overrideStartISO instanceof Date
    ? doc.overrideStartISO
    : ctx.start;

  const now = ctx.now.getTime();
  const s = Math.max(start.getTime(), ctx.start.getTime());
  const e = ctx.end.getTime();
  const period = Math.max(1, e - s + 1); // ms
  const elapsed = Math.max(0, Math.min(now - s, period));
  const frac = Math.min(1, elapsed / period);

  const base = 150 * frac;
  const extra = Number.isFinite(doc.extra) ? Math.max(0, doc.extra) : 0;
  const value = base + extra;

  return { value, parts: { base, extra }, start, end: ctx.end, now: ctx.now };
}

/* ---------- routes ---------- */

// GET /api/jackpot
// -> { ok:true, value:Number, ctx:{ key, startISO, endISO, nowISO }, parts:{ base, extra } }
r.get("/", async (_req, res) => {
  try {
    const ctx = monthContext();
    const doc = await getOrCreate(ctx.key);
    const out = computeValue(doc, ctx);
    res.json({
      ok: true,
      value: out.value,
      ctx: {
        key: ctx.key,
        startISO: out.start.toISOString(),
        endISO: out.end.toISOString(),
        nowISO: out.now.toISOString(),
      },
      parts: {
        base: out.parts.base,
        extra: out.parts.extra,
      },
    });
  } catch (e) {
    console.error("[jackpot] GET failed:", e?.message);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// POST /api/jackpot/contribute { amount:Number, source?, username? }
// -> { ok:true, value:Number }
r.post("/contribute", async (req, res) => {
  try {
    const amount = Number(req.body?.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ ok: false, error: "bad_amount" });
    }

    const ctx = monthContext();
    const doc = await getOrCreate(ctx.key);
    doc.extra = Math.max(0, (Number(doc.extra) || 0) + amount);
    await doc.save();

    const out = computeValue(doc, ctx);
    res.json({ ok: true, value: out.value });
  } catch (e) {
    console.error("[jackpot] contribute failed:", e?.message);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// POST /api/jackpot/reset  (admin only)
// -> { ok:true, value:Number }
r.post("/reset", requireAdmin, async (_req, res) => {
  try {
    const ctx = monthContext();
    const doc = await getOrCreate(ctx.key);

    // Reset current month: start over & clear extras
    doc.overrideStartISO = new Date();
    doc.extra = 0;
    await doc.save();

    const out = computeValue(doc, ctx);
    res.json({ ok: true, value: out.value });
  } catch (e) {
    console.error("[jackpot] reset failed:", e?.message);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// (optional) GET /api/jackpot/debug (admin) -> raw doc + computed parts
r.get("/debug", requireAdmin, async (_req, res) => {
  try {
    const ctx = monthContext();
    const doc = await getOrCreate(ctx.key);
    const out = computeValue(doc, ctx);
    res.json({
      ok: true,
      doc,
      computed: {
        value: out.value,
        base: out.parts.base,
        extra: out.parts.extra,
        startISO: out.start.toISOString(),
        endISO: out.end.toISOString(),
        nowISO: out.now.toISOString(),
      },
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default r;
