// backend/models/pvp/pvp.service.js
let data = {
  config: { entryFee: 0 },
  rounds: [] // [{ id, leftGame, rightGame, createdAt }]
};

export function getConfig(){ return data.config; }
export function setConfig(next = {}){ data.config = { ...data.config, ...next }; return data.config; }

export function getAllRounds(){ return data.rounds.slice(); }
export function resetRounds(){ data.rounds = []; }
export function addRound({ id, leftGame, rightGame, entryFee }){
  const round = { id: String(id), leftGame, rightGame, entryFee: Number(entryFee) || 0, createdAt: new Date().toISOString() };
  const idx = data.rounds.findIndex(r => r.id === round.id);
  if (idx >= 0) data.rounds[idx] = round; else data.rounds.push(round);
  return round;
}

export function joinRound({ username }){
  // skeleton for later — accept any username to keep things moving
  return { ok:true, joined:true, username:String(username||"guest") };
}
