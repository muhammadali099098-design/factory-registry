// sheet-store.js — СУБД на Google-таблице через официальный Google Sheets API (сервисный аккаунт).
// Надёжная запись/чтение, без блокировок. Не требует диска и компиляции.
// Если GOOGLE_SA_JSON не задан — локальный JSON-файл (для проверки).
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { JWT } from "google-auth-library";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || __dirname;
const JSON_FILE = path.join(DATA_DIR, "db.json");

const SA_JSON = (process.env.GOOGLE_SA_JSON || "").trim();
const SPREADSHEET_ID = (process.env.GOOGLE_SPREADSHEET_ID || "").trim();
const SCOPES = ["https://www.googleapis.com/auth/spreadsheets"];

const EMPTY = { factories: [], users: [], settings: [], audit: [] };

// Листы и колонки (совпадают с теми, что создавались скриптом)
const SHEETS = {
  factories: { name: "Заводы", cols: ["id","name","city","products","reliability","moq","lead_time","payment","certifications","notes","contacts","created_by","updated_by","created_at","updated_at"] },
  users: { name: "Пользователи", cols: ["id","name","email","password_hash","role","created_at"] },
  settings: { name: "Настройки", cols: ["key","value"] },
  audit: { name: "Журнал", cols: ["id","user_id","user_name","action","factory_id","factory_name","detail","created_at"] },
};

let jwtClient = null;
function getJwt() {
  if (!SA_JSON) return null;
  if (!jwtClient) {
    const sa = JSON.parse(SA_JSON);
    jwtClient = new JWT({ email: sa.client_email, key: sa.private_key, scopes: SCOPES });
  }
  return jwtClient;
}
async function apiCall({ method, range, values }) {
  const c = getJwt();
  const base = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(SPREADSHEET_ID)}/values/${encodeURIComponent(range)}`;
  if (method === "GET") {
    const r = await c.request({ url: base });
    return r.data.values || [];
  }
  const r = await c.request({ url: `${base}?valueInputOption=RAW`, method: "PUT", data: { values } });
  return r.data;
}

export function isGoogle() {
  return !!SA_JSON && !!SPREADSHEET_ID;
}

async function readSheet(kind) {
  const meta = SHEETS[kind];
  const vals = await apiCall({ method: "GET", range: `${meta.name}!A1:${String.fromCharCode(64 + meta.cols.length)}` });
  const out = [];
  if (vals.length <= 1) return out;
  for (let i = 1; i < vals.length; i++) {
    const row = vals[i];
    if (!row[1]) continue;
    const o = {};
    meta.cols.forEach((c, idx) => { o[c] = row[idx] ?? ""; });
    if (kind === "factories") {
      if (typeof o.products === "string") o.products = o.products.split(",").map((s) => s.trim()).filter(Boolean);
      if (typeof o.contacts === "string" && o.contacts) { try { o.contacts = JSON.parse(o.contacts); } catch { o.contacts = []; } }
    }
    out.push(o);
  }
  return out;
}

async function writeSheet(kind, list) {
  const meta = SHEETS[kind];
  const rows = [meta.cols];
  for (const item of list || []) {
    const row = meta.cols.map((k) => {
      let v = item ? item[k] : "";
      if (k === "products" && Array.isArray(v)) v = v.join(",");
      if (k === "contacts" && Array.isArray(v)) v = JSON.stringify(v);
      return v === undefined || v === null ? "" : v;
    });
    rows.push(row);
  }
  await apiCall({ method: "PUT", range: `${meta.name}!A1`, values: rows });
}

export async function fetchAll() {
  if (isGoogle()) {
    const [factories, users, settings, audit] = await Promise.all([
      readSheet("factories"), readSheet("users"), readSheet("settings"), readSheet("audit"),
    ]);
    return { factories, users, settings, audit };
  }
  return readJson();
}

export async function savePatch(patch) {
  if (isGoogle()) {
    const jobs = [];
    for (const k of ["factories", "users", "settings", "audit"]) {
      if (patch[k] !== undefined) jobs.push(writeSheet(k, patch[k]));
    }
    await Promise.all(jobs);
    return;
  }
  const data = readJson();
  for (const k of ["factories", "users", "settings", "audit"]) {
    if (patch[k] !== undefined) data[k] = patch[k];
  }
  writeJson(data);
}

// ---------- Локальный JSON (только для проверки без Google) ----------
function readJson() {
  if (fs.existsSync(JSON_FILE)) {
    try { return { ...EMPTY, ...JSON.parse(fs.readFileSync(JSON_FILE, "utf8")) }; }
    catch { return { ...EMPTY }; }
  }
  return { ...EMPTY };
}
function writeJson(data) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(JSON_FILE, JSON.stringify(data));
}