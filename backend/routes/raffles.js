// backend/routes/raffles.js — minimal, single system (ESM)
import express from "express";
import mongoose from "mongoose";

const router = express.Router();
const mongoUp = () => mongoose?.connection?.readyState === 1;
const MEM_OK = String(process.env.ALLOW_MEMORY_FALLBACK || "true").toLowerCase() === "true";
const up = s => (s||"").toString().trim().toUpperCase();

/* ------------ Models ------------- */
let Raffle, RaffleEntry, KV;
try {
  const raffleSchema = new mongoose.Schema({
    id:      { type:String, unique:true, index:true },
    title:   { type:String, default:"" },
    open:    { type:Boolean, default:true },
    created: { type:Date, default:()=>new Date() },
    winner:  { user:{type:String, default:""}, ts:{type:Date} }
  }, { versionKey:false, collection:"raffles" });
  Raffle = mongoose.models.Raffle || mongoose.model("Raffle", raffleSchema);

  const entrySchema = new mongoose.Schema({
    rid:{ type:String, index:true },
    user:{ type:String, index:true },
    ts:{ type:Date, default:()=>new Date() },
  }, { versionKey:false, collection:"raffle_entries" });
  entrySchema.index({ rid:1, user:1 }, { unique:true });
  RaffleEntry = mongoose.models.RaffleEntry || mongoose.model("RaffleEntry", entrySchema);

  const kvSchema = new mongoose.Schema({
    key:{type:String, unique:true}, value: mongoose.Schema.Types.Mixed,
    ts:{type:Date, default:()=>new Date()}
  }, { versionKey:false, collection:"app_config" });
  KV = mongoose.models.KV || mongoose.model("KV", kvSchema);
} catch {}

/* --------- Memory fallback -------- */
const mem = {
  current: null,
  raffles: new Map(),   // id -> {id,title,open,created,winner?}
  entries: new Map(),   // rid -> [{user,ts}]
};

async function setCurrent(id){
  if (mongoUp() && KV){ await KV.updateOne({key:"raffle_current_id"},{$set:{value:id,ts:new Date()}},{upsert:true}); }
  else { mem.current = id; }
}
async function getCurrent(){
  if (mongoUp() && KV){ const d = await KV.findOne({key:"raffle_current_id"}).lean(); return d?.value || null; }
  return mem.current || null;
}
async function ensureRaffle(id,title){
  if (mongoUp() && Raffle){
    await Raffle.updateOne({id},{ $setOnInsert:{id, title:title||id, open:true, created:new Date()} },{upsert:true});
  } else {
    if (!mem.raffles.has(id)) mem.raffles.set(id,{id, title:title||id, open:true, created:new Date(), winner:null});
  }
}
async function getInfo(id){
  if (mongoUp() && Raffle) return await Raffle.findOne({id}).lean();
  return mem.raffles.get(id) || null;
}

/* ========== ADMIN: create/open/current/list ========== */
// POST /api/raffles/create { id, title? }
router.post("/create", async (req,res)=>{
  const id=(req.body?.id||"").trim(); if(!id) return res.status(400).json({ok:false,error:"bad_id"});
  const title=(req.body?.title||id).trim();
  await ensureRaffle(id,title);
  await setCurrent(id);
  if (mongoUp() && Raffle) await Raffle.updateOne({id},{ $set:{ open:true, winner:null } });
  else { const r=mem.raffles.get(id); if(r){ r.open=true; r.winner=null; } }
  res.json({ok:true,id,title});
});

// PUT /api/raffles/:id/open { open: boolean }
router.put("/:id/open", async (req,res)=>{
  const id=(req.params.id||"").trim(); const open=!!req.body?.open;
  if(!id) return res.status(400).json({ok:false,error:"bad_id"});
  if (mongoUp() && Raffle) await Raffle.updateOne({id},{ $set:{open} });
  else { const r=mem.raffles.get(id)||{id,title:id}; r.open=open; mem.raffles.set(id,r); }
  res.json({ok:true,id,open});
});

// PUT /api/raffles/current { id }
router.put("/current", async (req,res)=>{
  const id=(req.body?.id||"").trim(); if(!id) return res.status(400).json({ok:false,error:"bad_id"});
  await setCurrent(id); res.json({ok:true,id});
});

// GET /api/raffles/list?open=0|1
router.get("/list", async (req,res)=>{
  const onlyOpen = String(req.query.open||"").trim()==="1";
  if (mongoUp() && Raffle){
    const rows = await Raffle.find(onlyOpen?{open:true}:{}, { _id:0 }).sort({created:-1}).lean();
    return res.json(rows);
  }
  if (!MEM_OK) return res.json([]);
  const arr = Array.from(mem.raffles.values()).sort((a,b)=>b.created - a.created);
  res.json(onlyOpen?arr.filter(r=>r.open):arr);
});

// GET /api/raffles/public (current raffle, with winner if set)
router.get("/public", async (_req,res)=>{
  const id = await getCurrent();
  if (!id) return res.json({ok:true,active:false});
  const info = await getInfo(id);
  res.json({ok:true,active:!!info,id,title:info?.title||id,open:!!info?.open,winner:info?.winner||null});
});

/* ========== ENTRIES (player) ========== */
// GET /api/raffles/:id/entries
router.get("/:id/entries", async (req,res)=>{
  const rid=(req.params.id||"").trim(); if(!rid) return res.status(400).json({ok:false,error:"bad_id"});
  if (mongoUp() && RaffleEntry){
    const rows = await RaffleEntry.find({rid}).sort({ts:1}).lean();
    return res.json({ok:true,entries:rows.map(r=>({user:r.user,ts:r.ts}))});
  }
  if (!MEM_OK) return res.status(503).json({ok:false,reason:"DB_OFFLINE"});
  res.json({ok:true,entries:(mem.entries.get(rid)||[])});
});

// POST /api/raffles/:id/entries  { user }  (keeps your existing route)
router.post("/:id/entries", async (req,res)=>{
  const rid=(req.params.id||"").trim(); const user=up(req.body?.user||"");
  if(!rid||!user) return res.status(400).json({ok:false,error:"bad_input"});
  const info = await getInfo(rid); if(!info) return res.status(404).json({ok:false,error:"not_found"});
  if(!info.open) return res.status(403).json({ok:false,error:"closed"});

  if (mongoUp() && RaffleEntry){
    try{
      await RaffleEntry.updateOne({rid,user},{ $setOnInsert:{rid,user}, $set:{ts:new Date()} },{upsert:true});
      return res.json({ok:true});
    }catch(e){ if(e?.code===11000) return res.json({ok:true,already:true}); return res.status(500).json({ok:false,error:e?.message||"db_error"}); }
  }
  if (!MEM_OK) return res.status(503).json({ok:false,reason:"DB_OFFLINE"});
  const list = mem.entries.get(rid)||[];
  if (!list.some(x=>x.user===user)) list.push({user,ts:new Date().toISOString()});
  mem.entries.set(rid,list);
  res.json({ok:true});
});

/* ========== WINNER (admin publishes; player reads) ========== */
// POST /api/raffles/:id/draw  -> { winner }
router.post("/:id/draw", async (req,res)=>{
  const rid=(req.params.id||"").trim(); if(!rid) return res.status(400).json({ok:false,error:"bad_id"});
  let entries=[];
  if (mongoUp() && RaffleEntry) entries = await RaffleEntry.find({rid}).lean();
  else if (MEM_OK) entries = mem.entries.get(rid)||[];
  else return res.status(503).json({ok:false,reason:"DB_OFFLINE"});
  if (!entries.length) return res.status(400).json({ok:false,error:"no_entries"});

  const pick = entries[Math.floor(Math.random()*entries.length)];
  const win = { user: up(pick.user), ts: new Date() };
  if (mongoUp() && Raffle) await Raffle.updateOne({id:rid},{ $set:{winner:win, open:false} });
  else { const r=mem.raffles.get(rid)||{id:rid,title:rid}; r.winner=win; r.open=false; mem.raffles.set(rid,r); }
  res.json({ok:true,winner:win});
});

// GET /api/raffles/:id/winner -> { winner }
router.get("/:id/winner", async (req,res)=>{
  const rid=(req.params.id||"").trim(); if(!rid) return res.status(400).json({ok:false,error:"bad_id"});
  const info = await getInfo(rid);
  res.json({ok:true,winner:info?.winner||null});
});

export default router;
