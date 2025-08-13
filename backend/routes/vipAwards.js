// backend/routes/vipAwards.js
import { Router } from "express";
import VIPAward from "../models/vip/VIPAward.js";
import requireAdmin from "../middleware/auth.js";

const r = Router();

// GET all awards
r.get("/", async (_req, res) => {
  try{
    const rows = await VIPAward.find({}).sort({ createdAt: 1 }).lean();
    res.json(rows);
  }catch(e){
    res.status(500).json({ ok:false, error:"server_error" });
  }
});

// POST create/update single award
r.post("/", requireAdmin, async (req, res) => {
  try{
    const { id, ...rest } = req.body || {};
    if (!id) return res.status(400).json({ ok:false, error:"missing_id" });
    const doc = await VIPAward.findOneAndUpdate({ id }, { $set: { id, ...rest, updatedAt: new Date() } }, { upsert:true, new:true });
    res.status(201).json({ ok:true, award: doc });
  }catch(e){
    res.status(500).json({ ok:false, error:"server_error" });
  }
});

// POST /bulk replace entire collection
r.post("/bulk", requireAdmin, async (req, res) => {
  try{
    const list = Array.isArray(req.body) ? req.body : [];
    if (!Array.isArray(list)) return res.status(400).json({ ok:false, error:"bad_payload" });
    const ops = list.map(x => ({
      updateOne: {
        filter: { id: String(x.id || "") },
        update: { $set: { ...x, id: String(x.id || ""), updatedAt: new Date() } },
        upsert: true
      }
    }));
    if (ops.length) await VIPAward.bulkWrite(ops, { ordered:false });
    const keepIds = list.map(x => String(x.id || ""));
    await VIPAward.deleteMany({ id: { $nin: keepIds } });
    const out = await VIPAward.find({}).sort({ createdAt: 1 }).lean();
    res.json(out);
  }catch(e){
    res.status(500).json({ ok:false, error:"server_error" });
  }
});

export default r;
