// backend/models/Jackpot.js
import mongoose from "mongoose";

const JackpotSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true, index: true }, // "YYYY-MM"
  overrideStartISO: { type: Date, default: null },                   // manual start date for current month
  extra: { type: Number, default: 0 },                               // contributions beyond base
  updatedAt: { type: Date, default: Date.now }
});

export default mongoose.model("Jackpot", JackpotSchema);
