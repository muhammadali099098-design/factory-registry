// sheet-store.js — данные в Google-таблице через официальный Sheets API (сервисный аккаунт).
// Оптимизировано: 1 запрос на все листы (batchGet/batchUpdate) + кэш, чтобы не исчерпать лимит.
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
const CACHE_TTL = 20000; // 20 сек кэш

const SHEETS = {
  factories: { name: "Заводы", cols: ["id","name","city","products","reliability","moq","lead_time","payment","certifications","notes","contacts","created_by","updated_by","created_at","updated_at"] },
  users: { name: "Пользователи", cols: ["id","name","email","password_hash","role","created_at"] },
  settings: { name: "Настройки", cols: ["key","value"] },
  audit: { name: "Журнал", cols: ["id","user_id","user_name","action","factory_id","factory_name","detail","created_at"] },
};

let jwtClient = null;
let cache = null;
let cacheAt = 0;
let chain = Promise.resolve();

// Последовательный запуск: не даёт одновременным запросам терять данные
function serialize(fn) {
  const run = chain.then(fn, fn);
  chain = run.catch(() => {});
  return run;
}

function getJwt() {
  if (jwtClient) return jwtClient;
  const sa = JSON.parse(SA_JSON);
  jwtClient = new JWT({ email: sa.client_email, key: sa.private_key, scopes: SCOPES });
  return jwtClient;
}

async function ensureSheets() {
  const c = getJwt();
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(SPREADSHEET_ID)}?fields=sheets.properties.title`;
  const r = await c.request({ url });
  const existing = new Set((r.data.sheets || []).map((s) => s.properties.title));
  const need = Object.values(SHEETS).map((s) => s.name).filter((n) => !existing.has(n));
  if (need.length) {
    const url2 = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(SPREADSHEET_ID)}:batchUpdate`;
    await c.request({
      url: url2, method: "POST",
      data: { requests: need.map((title) => ({ addSheet: { properties: { title } } })) },
    });
  }
}

async function readFromGoogle() {
  const c = getJwt();
  const ranges = Object.values(SHEETS).map((s) => `${s.name}!A1:${String.fromCharCode(64 + s.cols.length)}`);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(SPREADSHEET_ID)}/values:batchGet?${ranges.map((rg) => "ranges=" + encodeURIComponent(rg)).join("&")}`;
  const r = await c.request({ url });
  const out = {};
  (r.data.valueRanges || []).forEach((vr, i) => {
    const kind = Object.keys(SHEETS)[i];
    out[kind] = parseRows(kind, vr.values || []);
  });
  return { factories: out.factories || [], users: out.users || [], settings: out.settings || [], audit: out.audit || [] };
}

function parseRows(kind, vals) {
  const meta = SHEETS[kind];
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

async function writeToGoogle(patch) {
  const c = getJwt();
  const data = [];
  for (const k of Object.keys(SHEETS)) {
    if (patch[k] === undefined) continue;
    const meta = SHEETS[k];
    const rows = [meta.cols];
    for (const item of patch[k] || []) {
      const row = meta.cols.map((col) => {
        let v = item ? item[col] : "";
        if (col === "products" && Array.isArray(v)) v = v.join(",");
        if (col === "contacts" && Array.isArray(v)) v = JSON.stringify(v);
        return v === undefined || v === null ? "" : v;
      });
      rows.push(row);
    }
    data.push({ range: `${meta.name}!A1`, values: rows });
  }
  if (!data.length) return;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(SPREADSHEET_ID)}/values:batchUpdate`;
  await c.request({ url, method: "POST", data: { valueInputOption: "RAW", data } });
}

export function isGoogle() { return !!SA_JSON && !!SPREADSHEET_ID; }

export async function fetchAll() {
  return serialize(async () => {
    if (cache && Date.now() - cacheAt < CACHE_TTL) return cache;
    if (!isGoogle()) return readJson();
    await ensureSheets();
    cache = await readFromGoogle();
    cacheAt = Date.now();
    return cache;
  });
}

export async function savePatch(patch) {
  return serialize(async () => {
    if (cache) {
      for (const k of Object.keys(SHEETS)) if (patch[k] !== undefined) cache[k] = patch[k];
      cacheAt = Date.now();
    }
    if (isGoogle()) {
      await writeToGoogle(patch);
      return;
    }
    const data = readJson();
    for (const k of Object.keys(SHEETS)) if (patch[k] !== undefined) data[k] = patch[k];
    writeJson(data);
  });
}

// ---------- Локальный JSON (только для проверки без Google) ----------
function readJson() {
  if (fs.existsSync(JSON_FILE)) {
    try { return { ...{ factories: [], users: [], settings: [], audit: [] }, ...JSON.parse(fs.readFileSync(JSON_FILE, "utf8")) }; }
    catch { return { factories: [], users: [], settings: [], audit: [] }; }
  }
  return { factories: [], users: [], settings: [], audit: [] };
}
function writeJson(data) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(JSON_FILE, JSON.stringify(data));
}