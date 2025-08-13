// config/db.js
import mongoose from "mongoose";

export async function connectDB(uri) {
  if (!uri) throw new Error("MONGO_URI missing");
  mongoose.set("strictQuery", true);
  await mongoose.connect(uri, { dbName: process.env.MONGO_DB || undefined });
  console.log("[mongo] connected");
}
