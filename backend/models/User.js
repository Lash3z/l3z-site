// backend/models/User.js
import mongoose from "mongoose";

const LedgerSchema = new mongoose.Schema(
  {
    delta: { type: Number, required: true },
    reason: { type: String, default: "" },
    ref: { type: String, default: "" },
    ts: { type: Date, default: Date.now }
  },
  { _id: false }
);

const UserSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, index: true, required: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    balance: { type: Number, default: 0 },
    points: { type: Number, default: 0 },
    currency: { type: String, default: process.env.WALLET_CURRENCY || "L3Z" },
    ledger: { type: [LedgerSchema], default: [] }
  },
  { timestamps: true }
);

export default mongoose.models.User || mongoose.model("User", UserSchema);
