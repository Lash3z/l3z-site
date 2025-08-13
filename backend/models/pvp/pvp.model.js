// This is just a placeholder in case you switch to MongoDB later
export class PvpRound {
  constructor({ id, leftGame, rightGame, entryFee = 0, createdAt = new Date() }) {
    this.id = id;
    this.leftGame = leftGame;
    this.rightGame = rightGame;
    this.entryFee = entryFee;
    this.createdAt = createdAt;
  }
}
