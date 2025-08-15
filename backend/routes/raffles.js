// backend/routes/raffles.js (ESM)
import express from "express";
import mongoose from "mongoose";

const router = express.Router();
const mongoUp = () => mongoose?.connection?.readyState === 1;
const MEM_OK = String(process.env.ALLOW_MEMORY_FALLBACK || "").toLowerCase() === "true";

// ---------- Models ----------
let Raffle, RaffleEntry, KV;
try {
  const raffleSchema = new mongoose.Schema({
    id: { type:String, unique:true, index:true },     // slug-like id you type in admin
    title: { type:String, default:"" },
    open: { type:Boolean, default:true },             // can accept entries
    created: { type:Date, default:()=>new Date() },
  }, { versionKey:false, collection:"raffles" });
  Raffle = mongoose.models.Raffle || mongoose.model("Raffle", raffleSchema);

  const entrySchema = new mongoose.Schema({
    rid: { type:String, index:true },
    user:{ type:String, index:true },
    ts:  { type:Date, default:()=>new Date() },
  }, { versionKey:false, collection:"raffle_entries" });
  entrySchema.index({ rid:1, user:1 }, { unique:true });
  RaffleEntry = mongoose.models.RaffleEntry || mongoose.model("RaffleEntry", entrySchema);

  const kvSchema = new mongoose.Schema({
    key: { type:String, unique:true },
    value: mongoose.Schema.Types.Mixed,
    ts: { type:Date, default:()=>new Date() }
  }, { versionKey:false, collection:"app_config" });
  KV = mongoose.models.KV || mongoose.model("KV", kvSchema);
} catch {}

// ---------- Memory fallback ----------
const mem = {
  current: process.env.DEFAULT_RAFFLE_ID || null,
  raffles: new Map(), // id -> {id,title,open,created}
  entries: new Map(), // rid -> [{user,ts}]
};
const up = s => (s||"").toString().trim().toUpperCase();

// helpers
async function setCurrent(id){
  if (!id) return false;
  if (mongoUp() && KV){
    await KV.updateOne({key:"raffle_current_id"},{$set:{value:String(id),ts:new Date()}},{upsert:true});
    return true;
  }
  mem.current = String(id); return true;
}
async function getCurrent(){
  if (mongoUp() && KV){
    const d = await KV.findOne({key:"raffle_current_id"}).lean();
    return d?.value || mem.current || null;
  }
  return mem.current || null;
}
async function ensureRaffle(id,title){
  if (mongoUp() && Raffle){
    await Raffle.updateOne({id:String(id)},{$setOnInsert:{id:String(id),title:String(title||id),open:true,created:new Date()}},{upsert:true});
    return true;
  }
  if (!mem.raffles.has(id)) mem.raffles.set(id,{id,title:title||id,open:true,created:new Date()});
  return true;
}
async function getRaffleInfo(id){
  if (mongoUp() && Raffle){
    return await Raffle.findOne({id}).lean();
  }
  return mem.raffles.get(id) || null;
}

// ---------- Routes ----------

// ADMIN: create and make current
router.post("/create", async (req,res)=>{
  const id = (req.body?.id||"").trim();
  const title = (req.body?.title||id).trim();
  if (!id) return res.status(400).json({ok:false,error:"bad_id"});
  await ensureRaffle(id,title);
  await setCurrent(id);
  if (mongoUp() && Raffle) await Raffle.updateOne({id}, {$set:{open:true}});
  else { const r=mem.raffles.get(id); if(r) r.open=true; }
  res.json({ok:true, id, title});
});

// ADMIN: open/close entries for a raffle
router.put("/:id/open", async (req,res)=>{
  const id = (req.params.id||"").trim();
  const open = !!req.body?.open;
  if (!id) return res.status(400).json({ok:false,error:"bad_id"});
  if (mongoUp() && Raffle){
    await Raffle.updateOne({id}, {$set:{open}});
  } else if (MEM_OK) {
    const r = mem.raffles.get(id) || {id, title:id, open};
    r.open = open; mem.raffles.set(id,r);
  } else return res.status(503).json({ok:false,error:"store_offline"});
  res.json({ok:true, id, open});
});

// ADMIN: set current (switch)
router.put("/current", async (req,res)=>{
  const id = (req.body?.id||"").trim();
  if (!id) return res.status(400).json({ok:false,error:"bad_id"});
  const ok = await setCurrent(id);
  res.json({ok, id});
});

// PUBLIC: what should players see?
router.get("/public", async (_req,res)=>{
  const id = await getCurrent();
  if (!id) return res.json({ok:true, active:false});
  const info = await getRaffleInfo(id);
  res.json({ok:true, active:!!info, id, title: info?.title||id, open: !!info?.open});
});

// PUBLIC: entries for current
router.get("/entries", async (_req,res)=>{
  const rid = await getCurrent();
  if (!rid) return res.json({ok:true, id:null, entries:[]});
  if (mongoUp() && RaffleEntry){
    const rows = await RaffleEntry.find({rid}).sort({ts:1}).lean();
    res.setHeader("X-Store","mongo");
    return res.json({ok:true, id:rid, entries: rows.map(r=>({user:r.user,ts:r.ts}))});
  }
  if (!MEM_OK) { res.setHeader("X-Store","offline"); return res.status(503).json({ok:false,reason:"DB_OFFLINE"}); }
  const arr = mem.entries.get(rid) || [];
  res.setHeader("X-Store","memory");
  res.json({ok:true, id:rid, entries: arr});
});

// PUBLIC: enter current
router.post("/enter", async (req,res)=>{
  const user = up(req.body?.user||"");
  if (!user) return res.status(400).json({ok:false,error:"bad_user"});
  const rid = await getCurrent();
  if (!rid) return res.status(400).json({ok:false,error:"no_current"});
  const info = await getRaffleInfo(rid);
  if (!info?.open) return res.status(403).json({ok:false,error:"closed"});

  if (mongoUp() && RaffleEntry){
    try{
      await RaffleEntry.updateOne(
        {rid, user}, { $setOnInsert:{rid,user}, $set:{ts:new Date()} }, { upsert:true }
      );
      res.setHeader("X-Store","mongo");
      return res.json({ok:true, id:rid});
    }catch(e){
      if (e?.code===11000){ res.setHeader("X-Store","mongo"); return res.json({ok:true, already:true, id:rid}); }
      return res.status(500).json({ok:false,error:e?.message||"db_error"});
    }
  }
  if (!MEM_OK) { res.setHeader("X-Store","offline"); return res.status(503).json({ok:false,reason:"DB_OFFLINE"}); }
  const list = mem.entries.get(rid) || [];
  if (!list.some(x=>x.user===user)) list.push({user, ts:new Date().toISOString()});
  mem.entries.set(rid, list);
  res.setHeader("X-Store","memory");
  res.json({ok:true, id:rid});
});

// (Optional) explicit ID endpoints for admin drill-down
router.get("/:id/entries", async (req,res)=>{
  const rid = (req.params.id||"").trim();
  if (!rid) return res.status(400).json({ok:false,error:"bad_id"});
  if (mongoUp() && RaffleEntry){
    const rows = await RaffleEntry.find({rid}).sort({ts:1}).lean();
    return res.json({ok:true, entries: rows.map(r=>({user:r.user, ts:r.ts}))});
  }
  if (!MEM_OK) return res.status(503).json({ok:false,reason:"DB_OFFLINE"});
  res.json({ok:true, entries: (mem.entries.get(rid)||[])});
});

export default router;
