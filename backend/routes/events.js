// backend/routes/events.js (ESM) — no global fetch required
import express from "express";
import mongoose from "mongoose";
import http from "http";
import https from "https";

const router = express.Router();

/* --------------------------- config / helpers --------------------------- */

const MEL_TZ = "Australia/Melbourne";
const DAY = 24 * 60 * 60 * 1000;

const defaultRules = {
  jackpotCurrency: "AUD",
  jackpotPerSubAUD: 2.50,
  lbx: {
    SUB_NEW: 10,
    SUB_RENEW: 5,
    SUB_GIFT_GIFTER_PER: 2,
    SUB_GIFT_RECIPIENT: 3,
  },
  caps: {
    eventLBXPerUserPerDay: 100, // subs/resubs/gifts combined
  },
  depositContributesJackpot: false,
  autoApprove: {
    subs: true,
    gifts: true,
    resubs: true,
    donations: false,
  },
};

const up = (s) => (s || "").toString().trim().toUpperCase();
const now = () => Date.now();

function melMonthKey(ts = Date.now()) {
  const fmt = new Intl.DateTimeFormat("en-AU", {
    timeZone: MEL_TZ,
    year: "numeric",
    month: "2-digit",
  });
  const parts = fmt.formatToParts(new Date(ts));
  const y = parts.find((p) => p.type === "year")?.value || "1970";
  const m = parts.find((p) => p.type === "month")?.value || "01";
  return `${y}-${m}`;
}

const hasMongo = !!(mongoose?.connection && mongoose.connection.readyState > 0);

/* --------------------------- tiny HTTP JSON helper ---------------------- */

function postJSON(url, payload) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(url);
      const isHttps = u.protocol === "https:";
      const body = Buffer.from(JSON.stringify(payload || {}));
      const opts = {
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname + (u.search || ""),
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": body.length,
        },
      };
      const req = (isHttps ? https : http).request(opts, (res) => {
        let data = "";
        res.on("data", (d) => (data += d));
        res.on("end", () => {
          const ok = res.statusCode >= 200 && res.statusCode < 300;
          let json = {};
          try { json = data ? JSON.parse(data) : {}; } catch {}
          resolve({ ok, status: res.statusCode, json });
        });
      });
      req.on("error", reject);
      req.write(body);
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

/* ------------------------------ Mongo models --------------------------- */

let EventDoc, RulesDoc, JackpotDoc, WalletDoc, LedgerDoc;

if (hasMongo) {
  const EventSchema = new mongoose.Schema(
    {
      provider: { type: String, index: true },
      eventId: { type: String, index: true },
      type: { type: String, index: true }, // SUB_NEW | SUB_RENEW | SUB_GIFT | TIP | ...
      user: { type: String, index: true, uppercase: true, trim: true },
      quantity: { type: Number, default: 1 },
      recipients: [{ type: String, uppercase: true, trim: true }],
      ts: { type: Number, index: true },
      applied: { type: Boolean, default: false, index: true },
      details: { type: Object, default: {} },
    },
    { collection: "l3z_events" }
  );
  EventSchema.index({ provider: 1, eventId: 1 }, { unique: true });

  const RulesSchema = new mongoose.Schema(
    {
      key: { type: String, unique: true, default: "main" },
      rules: { type: Object, default: defaultRules },
      updatedAt: { type: Number, default: () => Date.now() },
    },
    { collection: "l3z_rules" }
  );

  const JackpotSchema = new mongoose.Schema(
    {
      month: { type: String, unique: true, index: true }, // YYYY-MM (Melbourne)
      potAUD: { type: Number, default: 0 },
      updatedAt: { type: Number, default: () => Date.now() },
      ledger: [
        {
          ts: Number,
          deltaAUD: Number,
          reason: String,
          actor: String, // event source or "ADMIN"
        },
      ],
    },
    { collection: "l3z_jackpot" }
  );

  // Wallet/Ledger — compatible with your lbx router models
  const WalletSchema =
    mongoose.models.LbxWallet?.schema ||
    new mongoose.Schema(
      {
        user: { type: String, required: true, unique: true, uppercase: true, trim: true },
        balance: { type: Number, default: 0 },
        lastDaily: { type: Number, default: 0 },
        created: { type: Number, default: () => Date.now() },
      },
      { collection: "lbx_wallets" }
    );

  const LedgerSchema =
    mongoose.models.LbxLedger?.schema ||
    new mongoose.Schema(
      {
        user: { type: String, required: true, index: true, uppercase: true, trim: true },
        ts: { type: Number, default: () => Date.now(), index: true },
        delta: { type: Number, required: true },
        reason: { type: String, default: "" },
        balance: { type: Number, required: true },
      },
      { collection: "lbx_ledger" }
    );

  EventDoc = mongoose.models.L3ZEvent || mongoose.model("L3ZEvent", EventSchema);
  RulesDoc = mongoose.models.L3ZRules || mongoose.model("L3ZRules", RulesSchema);
  JackpotDoc = mongoose.models.L3ZJackpot || mongoose.model("L3ZJackpot", JackpotSchema);
  WalletDoc = mongoose.models.LbxWallet || mongoose.model("LbxWallet", WalletSchema);
  LedgerDoc = mongoose.models.LbxLedger || mongoose.model("LbxLedger", LedgerSchema);
}

/* ------------------------ In-memory fallbacks -------------------------- */

const mem = {
  rules: { ...defaultRules },
  events: [], // most recent first
  jackpot: new Map(), // month -> { potAUD, updatedAt, ledger:[] }
  eventCreditLog: [], // {user, ts, amount} for rolling-24h cap
};

function memGetJackpot(month) {
  if (!mem.jackpot.has(month)) {
    mem.jackpot.set(month, { potAUD: 0, updatedAt: now(), ledger: [] });
  }
  return mem.jackpot.get(month);
}

/* --------------------------- wallet crediting -------------------------- */

async function creditWallet(user, amount, reason) {
  user = up(user);
  if (hasMongo && WalletDoc && LedgerDoc) {
    const w = await WalletDoc.findOneAndUpdate(
      { user },
      { $setOnInsert: { created: now(), lastDaily: 0 }, $inc: { balance: +amount } },
      { upsert: true, new: true }
    );
    await LedgerDoc.create({
      user,
      ts: now(),
      delta: +amount,
      reason: String(reason || "ADJUST"),
      balance: w.balance,
    });
    return { user, balance: w.balance };
  }

  // Fallback: call our own API without relying on global fetch
  const PORT = process.env.PORT || 3000;
  const HOST = process.env.HOST || "127.0.0.1";
  const base = `http://${HOST}:${PORT}`;
  const resp = await postJSON(`${base}/api/wallet/credit`, {
    user,
    amount: +amount,
    reason: String(reason || "ADJUST"),
  });
  if (!resp.ok) throw new Error("wallet_credit_failed");
  return resp.json;
}

async function sumEventLBX24h(user) {
  const since = now() - DAY;
  user = up(user);
  if (hasMongo && LedgerDoc) {
    const rows = await LedgerDoc.find({
      user,
      ts: { $gte: since },
      reason: { $regex: /^EVENT:/ },
    }).select("delta").lean();
    return rows.reduce((a, r) => a + (Number(r.delta) || 0), 0);
  } else {
    return mem.eventCreditLog
      .filter((e) => up(e.user) === user && e.ts >= since)
      .reduce((a, r) => a + (Number(r.amount) || 0), 0);
  }
}

function recordMemEventCredit(user, amount) {
  mem.eventCreditLog.push({ user: up(user), amount: +amount, ts: now() });
  if (mem.eventCreditLog.length > 5000) {
    const since = now() - DAY;
    mem.eventCreditLog = mem.eventCreditLog.filter((e) => e.ts >= since);
  }
}

/* ----------------------------- rules storage --------------------------- */

async function getRules() {
  if (hasMongo && RulesDoc) {
    const r = await RulesDoc.findOne({ key: "main" }).lean();
    return r?.rules || { ...defaultRules };
  }
  return mem.rules;
}

async function setRules(next) {
  const merged = { ...(await getRules()), ...(next || {}) };
  if (hasMongo && RulesDoc) {
    await RulesDoc.updateOne(
      { key: "main" },
      { $set: { rules: merged, updatedAt: now() } },
      { upsert: true }
    );
    return merged;
  }
  mem.rules = merged;
  return merged;
}

/* --------------------------- jackpot accounting ------------------------ */

async function addToJackpotAUD(deltaAUD, actor) {
  const month = melMonthKey();
  if (hasMongo && JackpotDoc) {
    const doc = await JackpotDoc.findOneAndUpdate(
      { month },
      {
        $inc: { potAUD: +deltaAUD },
        $set: { updatedAt: now() },
        $push: { ledger: { ts: now(), deltaAUD: +deltaAUD, reason: "EVENT", actor: actor || "" } },
      },
      { upsert: true, new: true }
    );
    return { month: doc.month, potAUD: doc.potAUD, updatedAt: doc.updatedAt };
  } else {
    const j = memGetJackpot(month);
    j.potAUD = +(j.potAUD + +deltaAUD).toFixed(2);
    j.updatedAt = now();
    j.ledger.push({ ts: now(), deltaAUD: +deltaAUD, reason: "EVENT", actor: actor || "" });
    return { month, potAUD: j.potAUD, updatedAt: j.updatedAt };
  }
}

async function adjustJackpotAUD(deltaAUD, reason, actor = "ADMIN") {
  const month = melMonthKey();
  if (hasMongo && JackpotDoc) {
    const doc = await JackpotDoc.findOneAndUpdate(
      { month },
      {
        $inc: { potAUD: +deltaAUD },
        $set: { updatedAt: now() },
        $push: { ledger: { ts: now(), deltaAUD: +deltaAUD, reason: String(reason || "ADJUST"), actor } },
      },
      { upsert: true, new: true }
    );
    return { month: doc.month, potAUD: doc.potAUD, updatedAt: doc.updatedAt };
  } else {
    const j = memGetJackpot(month);
    j.potAUD = +(j.potAUD + +deltaAUD).toFixed(2);
    j.updatedAt = now();
    j.ledger.push({ ts: now(), deltaAUD: +deltaAUD, reason: String(reason || "ADJUST"), actor });
    return { month, potAUD: j.potAUD, updatedAt: j.updatedAt };
  }
}

async function readJackpot(month = melMonthKey()) {
  if (hasMongo && JackpotDoc) {
    const doc = await JackpotDoc.findOne({ month }).lean();
    return { month, potAUD: +(doc?.potAUD || 0), updatedAt: doc?.updatedAt || now(), ledger: doc?.ledger || [] };
  } else {
    const j = memGetJackpot(month);
    return { month, potAUD: +(j.potAUD || 0), updatedAt: j.updatedAt || now(), ledger: j.ledger || [] };
  }
}

/* ----------------------------- event ingest ---------------------------- */

function checkSecret(req) {
  const need = process.env.L3Z_HOOK_SECRET;
  if (!need) return true; // allow if not set (dev)
  const got = req.get("X-L3Z-Secret") || "";
  return got === need;
}

async function recordEvent(e) {
  if (hasMongo && EventDoc) {
    try {
      const doc = await EventDoc.create(e);
      return { id: doc._id?.toString(), created: true };
    } catch (err) {
      if (err?.code === 11000) {
        const doc = await EventDoc.findOne({ provider: e.provider, eventId: e.eventId }).lean();
        return { id: doc?._id?.toString(), created: false, existing: doc };
      }
      throw err;
    }
  } else {
    const exists = mem.events.find((x) => x.provider === e.provider && x.eventId === e.eventId);
    if (!exists) {
      mem.events.unshift({ ...e, id: `EVT-${Math.random().toString(36).slice(2, 10).toUpperCase()}` });
      mem.events = mem.events.slice(0, 1000);
      return { id: mem.events[0].id, created: true };
    }
    return { id: exists.id, created: false, existing: exists };
  }
}

async function markApplied(provider, eventId) {
  if (hasMongo && EventDoc) {
    await EventDoc.updateOne({ provider, eventId }, { $set: { applied: true } });
  } else {
    const it = mem.events.find((x) => x.provider === provider && x.eventId === eventId);
    if (it) it.applied = true;
  }
}

async function applyLBXWithCap(user, delta, cap, reason) {
  user = up(user);
  const used = await sumEventLBX24h(user);
  const room = cap - used;
  const give = Math.max(0, Math.min(room, delta));
  if (give <= 0) return { applied: 0, capped: true, used, cap };

  await creditWallet(user, give, reason);
  if (!hasMongo) recordMemEventCredit(user, give);
  return { applied: give, capped: give < delta, used: used + give, cap };
}

/* --------------------------------- routes ------------------------------- */

// webhook ingest
router.post("/hooks/events", async (req, res) => {
  try {
    if (!checkSecret(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

    const body = req.body || {};
    const provider = String(body.provider || "kick").toLowerCase();
    const eventId = String(body.event_id || body.id || "").trim();
    const type = String(body.type || "").toUpperCase();
    const ts = Number(body.ts || Date.now());
    const user = up(body.user || "");
    const qty = Math.max(1, Number(body.quantity || 1));
    const recipients = Array.isArray(body.recipients) ? body.recipients.map(up) : [];

    if (!eventId || !type) return res.status(400).json({ ok: false, error: "bad_payload" });

    const rules = await getRules();

    // record (idempotent)
    const rec = await recordEvent({
      provider, eventId, type, user, quantity: qty, recipients, ts, applied: false, details: body.meta || {},
    });
    if (!rec.created && rec.existing?.applied) {
      return res.json({ ok: true, idempotent: true });
    }

    let jackpotAdd = 0;
    const out = { wallet: [], jackpotAUD: 0, cap: rules.caps.eventLBXPerUserPerDay };

    if (type === "SUB_NEW") {
      const applied = await applyLBXWithCap(user, rules.lbx.SUB_NEW, rules.caps.eventLBXPerUserPerDay, "EVENT:SUB_NEW");
      out.wallet.push({ user, ...applied });
      jackpotAdd += rules.jackpotPerSubAUD;
    } else if (type === "SUB_RENEW") {
      const applied = await applyLBXWithCap(user, rules.lbx.SUB_RENEW, rules.caps.eventLBXPerUserPerDay, "EVENT:SUB_RENEW");
      out.wallet.push({ user, ...applied });
      jackpotAdd += rules.jackpotPerSubAUD;
    } else if (type === "SUB_GIFT") {
      const gApplied = await applyLBXWithCap(
        user,
        rules.lbx.SUB_GIFT_GIFTER_PER * qty,
        rules.caps.eventLBXPerUserPerDay,
        "EVENT:SUB_GIFT_GIFTER"
      );
      out.wallet.push({ user, ...gApplied });

      if (rules.lbx.SUB_GIFT_RECIPIENT > 0 && recipients.length) {
        for (const r of recipients) {
          const rApplied = await applyLBXWithCap(
            r,
            rules.lbx.SUB_GIFT_RECIPIENT,
            rules.caps.eventLBXPerUserPerDay,
            "EVENT:SUB_GIFT_RECIPIENT"
          );
          out.wallet.push({ user: r, ...rApplied });
        }
      }
      jackpotAdd += rules.jackpotPerSubAUD * qty;
    }

    if (jackpotAdd > 0) {
      const j = await addToJackpotAUD(jackpotAdd, `${type}:${user}`);
      out.jackpotAUD = j.potAUD;
    }

    await markApplied(provider, eventId);
    return res.json({ ok: true, result: out });
  } catch (e) {
    console.error("[hooks/events] error:", e);
    return res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

// rules get/set
router.get("/events/rules", async (_req, res) => {
  try { res.json({ ok: true, rules: await getRules() }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message || "server_error" }); }
});

router.put("/events/rules", async (req, res) => {
  try { res.json({ ok: true, rules: await setRules(req.body || {}) }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message || "server_error" }); }
});

// recent events
router.get("/events/recent", async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(500, Number(req.query.limit || 200)));
    if (hasMongo && EventDoc) {
      const rows = await EventDoc.find({}).sort({ ts: -1 }).limit(limit).lean();
      return res.json({ ok: true, events: rows });
    } else {
      return res.json({ ok: true, events: mem.events.slice(0, limit) });
    }
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

// jackpot API
router.get("/jackpot", async (_req, res) => {
  try {
    const j = await readJackpot(melMonthKey());
    res.json({ ok: true, month: j.month, currency: "AUD", pot: +(j.potAUD || 0), updatedAt: j.updatedAt });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

router.post("/jackpot/adjust", async (req, res) => {
  try {
    const delta = Number(req.body?.deltaAUD || 0);
    const reason = String(req.body?.reason || "ADJUST");
    if (!delta) return res.status(400).json({ ok: false, error: "delta_required" });
    const j = await adjustJackpotAUD(delta, reason, "ADMIN");
    res.json({ ok: true, month: j.month, currency: "AUD", pot: j.potAUD, updatedAt: j.updatedAt });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "server_error" });
  }
});

export default router;
