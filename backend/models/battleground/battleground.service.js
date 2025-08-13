// backend/models/battleground/battleground.service.js
let state = {
  config: { isOpen: false, currentEventId: null },
  predictions: {} // { [eventId]: [ {username, picks, score, at} ] }
};

export function getConfig(){ return state.config; }
export function setConfig(next = {}){
  state.config = { ...state.config, ...next };
  return state.config;
}
export function openEvent(eventId){
  state.config.isOpen = true;
  state.config.currentEventId = String(eventId || Date.now());
  if (!state.predictions[state.config.currentEventId]) state.predictions[state.config.currentEventId] = [];
  return { ok:true, config: state.config };
}
export function closeEvent(){
  state.config.isOpen = false;
  return { ok:true, config: state.config };
}
export function resetEvent(eventId){
  if (eventId) delete state.predictions[eventId];
  else state.predictions = {};
  return { ok:true };
}
export function listPredictions(eventId){
  const id = eventId || state.config.currentEventId;
  return (state.predictions[id] || []).slice().reverse();
}
export function addPredictions({ username, eventId, picks = [], score = null }){
  const id = eventId || state.config.currentEventId;
  if (!id) return { ok:false, error:"no_active_event" };
  const row = { username: String(username || "guest"), picks, score, at: new Date().toISOString() };
  state.predictions[id] = state.predictions[id] || [];
  state.predictions[id].push(row);
  return { ok:true, row };
}
