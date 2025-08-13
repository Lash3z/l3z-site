// backend/lib/store.js (ESM)
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const STORE_DIR = path.resolve(__dirname, '../_store');
const STORE_FILE = path.join(STORE_DIR, 'db.json');

function ensureStore() {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
  if (!fs.existsSync(STORE_FILE)) {
    const seed = { users: [], meta: { lastId: 0 } };
    fs.writeFileSync(STORE_FILE, JSON.stringify(seed, null, 2), 'utf-8');
  }
}

function load() {
  ensureStore();
  const raw = fs.readFileSync(STORE_FILE, 'utf-8');
  try {
    return JSON.parse(raw);
  } catch (e) {
    const seed = { users: [], meta: { lastId: 0 } };
    fs.writeFileSync(STORE_FILE, JSON.stringify(seed, null, 2), 'utf-8');
    return seed;
  }
}

function save(db) {
  fs.writeFileSync(STORE_FILE, JSON.stringify(db, null, 2), 'utf-8');
}

export function nowISO() {
  return new Date().toISOString();
}

export function nextId(db, prefix = 'id') {
  if (!db.meta) db.meta = { lastId: 0 };
  db.meta.lastId = (db.meta.lastId || 0) + 1;
  return `${prefix}-${db.meta.lastId}`;
}

export async function readOnly(fn) {
  const db = load();
  return await fn(db);
}

export async function mutate(fn) {
  const db = load();
  const out = await fn(db);
  save(db);
  return out;
}
