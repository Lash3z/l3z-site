export class BonusHunt {
  constructor({ id, huntType, games, createdAt = new Date() }) {
    this.id = id;
    this.huntType = huntType;
    this.games = games;
    this.createdAt = createdAt;
  }
}
