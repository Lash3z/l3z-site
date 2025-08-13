// /config/paths.js
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Project root (two levels up from /config)
export const ROOT_DIR = path.resolve(__dirname, "..");
export const STATIC_ROOT = ROOT_DIR; // you’re serving the repo root
export const ADMIN_STATIC_DIR = path.join(ROOT_DIR, "pages", "dashboard", "admin");
export const ADMIN_LOGIN_HTML = path.join(ROOT_DIR, "pages", "dashboard", "home", "admin_login.html");
export const INDEX_HTML = path.join(ROOT_DIR, "index.html");
