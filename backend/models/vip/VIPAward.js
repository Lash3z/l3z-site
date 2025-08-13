import mongoose from "mongoose";

const VIPAwardSchema = new mongoose.Schema({
  id: { type: String, unique: true, index: true },   // UI id
  tier: { type: String, default: "Bronze" },
  title: { type: String, default: "" },
  description: { type: String, default: "" },
  badgeUrl: { type: String, default: "" },
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

export default mongoose.models.VIPAward || mongoose.model("VIPAward", VIPAwardSchema);
