export class LeaderboardEntry {
  constructor({ username, points = 0 }) {
    this.username = username;
    this.points = points;
  }
}
