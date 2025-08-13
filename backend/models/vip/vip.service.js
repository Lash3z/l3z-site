// backend/models/vip/vip.service.js
// Simple in-memory VIP awards store. Swap to Mongo later if you want persistence.
const awards = [
  // sample:
  // { tier: "VIP Bronze", description: "Priority entry in giveaways" },
];

export function getVipAwards() {
  return awards.slice(-200);
}

export function addVipAward({ tier, description }) {
  const item = {
    tier: String(tier || "VIP"),
    description: String(description || ""),
  };
  awards.push(item);
  return item;
}
