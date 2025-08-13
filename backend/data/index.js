// backend/data/index.js
// Central static data for the LASH3Z backend

/* ---------- Slot Lists ---------- */

// Mega Hunt slot list
export const megaHuntGames = [
  "Wild Wild Riches Megaways",
  "Extra Juicy Megaways",
  "Power of Thor Megaways",
  "Lucky Fishing Megaways",
  "Power of Merlin Megaways",
  "Muertos Multiplier Megaways",
  "Yum Yum Powerways",
  "Raven Rising",
  "Eastern Emeralds Megaways",
  "Rocket Blast Megaways",
  "Mammoth Gold Megaways",
  "Merlins Revenge Megaways",
  "Cherry Pop",
  "Bounty Pop"
];

// Super Hunt slot list (confirmed final)
export const superHuntGames = [
  "2 Wild 2 Die",
  "Bloodthirst",
  "Book of Time",
  "Bouncy Bombs",
  "Chaos Crew",
  "Cursed Seas",
  "Densho",
  "Dork Unit",
  "Double Rainbow",
  "Drop 'Em",
  "Duba Dice",
  "F.R.I.E.S",
  "Forest Fortune",
  "Frank's Farm",
  "Fruit Duel",
  "Hand of Anubis",
  "Itero",
  "King Carrot",
  "Le Bandit",
  "Le Bandit: Dusky Vengeance",
  "Magic Piggy",
  "Mayan Stackways",
  "Miami Multiplier",
  "Omnom",
  "Outlaws Inc",
  "Pug Life",
  "RIP City",
  "Rock Bottom",
  "Rotten",
  "Spirit of the Beast",
  "Stack'Em",
  "Stormforged",
  "The Bowery Boys",
  "The Haunted Circus",
  "The Rave",
  "The Respinners",
  "Time Spinners",
  "Tilt 'n' Turn",
  "Toshi Video Club",
  "Undead Fortune",
  "Wanted: Dead or a Wild",
  "Warrior Ways",
  "Wild Fishing Wild Ways",
  "Wild Hogs"
];

// Player Hunt will be dynamic (loaded from DB per session)
export const playerHuntGames = [];

/* ---------- Game Config ---------- */

// Use env currency everywhere for consistency with wallet
const CURRENCY = process.env.WALLET_CURRENCY || "L3Z";

// Battleground entry fee (can be overridden via file/admin)
export const battlegroundConfig = {
  entryFee: 10,
  currency: CURRENCY
};

// Bonus Hunt config defaults
export const bonusHuntConfig = {
  minBet: 0.10,
  maxBet: 5.00,
  breakEvenMultiplier: 100
};

// PVP config defaults
export const pvpConfig = {
  entryFee: 20,
  currency: CURRENCY
};

/* ---------- Dummy Leaderboard Data (for testing) ---------- */
export const leaderboardSeed = [
  { username: "Lash3z", mega: 5, super: 3, player: 2, tournament: 10 },
  { username: "Viewer1", mega: 4, super: 4, player: 1, tournament: 6 },
  { username: "Viewer2", mega: 2, super: 1, player: 3, tournament: 4 }
];
