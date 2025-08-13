export class BGSide {
  constructor({ name = "", provider = "", img = "" } = {}) {
    this.name = name;
    this.provider = provider;
    this.img = img;
  }
}
export class BGRound {
  constructor({ i = 0, a = new BGSide(), b = new BGSide() } = {}) {
    this.i = i; // 0..7
    this.a = a;
    this.b = b;
  }
}
export class BGConfig {
  constructor({ eventId = null, isOpen = false, rounds = [] } = {}) {
    this.eventId = eventId;
    this.isOpen = isOpen;
    this.rounds = rounds;
  }
}
export class BGPrediction {
  constructor({ id, username, eventId, i, winner, score = null, createdAt = new Date().toISOString() }) {
    this.id = id;
    this.username = username;
    this.eventId = eventId;
    this.i = i;
    this.winner = winner; // 'A'|'B'
    this.score = score;   // {a:2,b:1} optional
    this.createdAt = createdAt;
  }
}
