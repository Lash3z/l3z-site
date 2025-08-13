import fs from "fs";
import path from "path";

const leaderboardFile = path.join(process.cwd(), "data", "leaderboard.json");

export function getLeaderboard() {
  if (!fs.existsSync(leaderboardFile)) return [];
  return JSON.parse(fs.readFileSync(leaderboardFile, "utf-8"));
}

export function updateLeaderboard(player, points) {
  const lb = getLeaderboard();
  const existing = lb.find(p => p.username === player);
  if (existing) {
    existing.points += points;
  } else {
    lb.push({ username: player, points });
  }
  fs.writeFileSync(leaderboardFile, JSON.stringify(lb, null, 2));
}
