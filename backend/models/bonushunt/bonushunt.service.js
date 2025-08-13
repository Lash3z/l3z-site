// backend/models/bonushunt/bonushunt.service.js
const hunts = []; // { id, huntType, games:[], createdAt }

export function getBonusHunts() {
  return hunts.slice(-200);
}

export function addBonusHunt(h) {
  const out = {
    id: h.id,
    huntType: h.huntType,
    games: Array.isArray(h.games) ? h.games : [],
    createdAt: h.createdAt || new Date().toISOString()
  };
  hunts.push(out);
  return out;
}
