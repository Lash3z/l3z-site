// /config/env.js
import dotenv from "dotenv";
dotenv.config();

const env = (k, def = "") => (process.env[k] ?? def);

export const CFG = {
  NODE_ENV: env("NODE_ENV", "development"),
  PORT: parseInt(env("PORT", "3000"), 10),
  ADMIN_USER: env("ADMIN_USER", ""),
  ADMIN_PASS: env("ADMIN_PASS", ""),
  ADMIN_PASS_HASH: env("ADMIN_PASS_HASH", ""),
  ADMIN_SECRET: env("ADMIN_SECRET", ""),
  // App knobs we’ll use soon:
  GIFTED_SUB_INCREMENT: parseFloat(env("GIFTED_SUB_INCREMENT", "2.50")),
  JACKPOT_TARGET: parseFloat(env("JACKPOT_TARGET", "150")),
  JACKPOT_PERIOD_DAYS: parseInt(env("JACKPOT_PERIOD_DAYS", "28"), 10)
};

export function validateAdminEnv(logFn = console.warn) {
  if (!CFG.ADMIN_USER) logFn("[env-check] ADMIN_USER is missing.");
  if (!CFG.ADMIN_SECRET) logFn("[env-check] ADMIN_SECRET is missing (JWT will fail).");
  if (!CFG.ADMIN_PASS && !CFG.ADMIN_PASS_HASH) {
    logFn("[env-check] Set ADMIN_PASS or ADMIN_PASS_HASH to log in.");
  }
}
