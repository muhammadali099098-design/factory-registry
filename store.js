// store.js — хранилище заводов.
// Если задано GOOGLE_SHEET_WEBAPP_URL — данные живут в Google-таблице (через Apps Script).
// Иначе — локальная SQLite (для локальной проверки / резерв).
import db from "./db.js";

const WEBAPP_URL = (process.env.GOOGLE_SHEET_WEBAPP_URL || "").trim();

function now() {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}

// ---------- SQLite: строка → объект ----------
function rowToFactory(r) {
  const createdBy = r.created_by_id ? db.prepare("SELECT name FROM users WHERE id = ?").get(r.created_by_id)?.name || null : null;
  const updatedBy = r.updated_by_id ? db.prepare("SELECT name FROM users WHERE id = ?").get(r.updated_by_id)?.name || null : null;
  const contacts = db.prepare("SELECT id, name, role, wechat, whatsapp, phone, email FROM contacts WHERE factory_id = ? ORDER BY id").all(r.id)
    .map((c) => ({ name: c.name, role: c.role, wechat: c.wechat, whatsapp: c.whatsapp, phone: c.phone, email: c.email }));
  return {
    id: r.id, name: r.name, city: r.city,
    products: r.products ? r.products.split(",").map((s) => s.trim()).filter(Boolean) : [],
    reliability: r.reliability, moq: r.moq, leadTime: r.lead_time, payment: r.payment,
    certifications: r.certifications, notes: r.notes, contacts,
    createdBy, updatedBy, createdAt: r.created_at, updatedAt: r.updated_at,
  };
}

// ---------- API хранилища ----------
export async function listFactories() {
  if (WEBAPP_URL) {
    const r = await fetch(WEBAPP_URL);
    if (!r.ok) throw new Error("Не удалось прочитать Google-таблицу");
    const d = await r.json();
    return Array.isArray(d.factories) ? d.factories : [];
  }
  return db.prepare("SELECT * FROM factories").all().map(rowToFactory);
}

export async function replaceAll(factories) {
  if (WEBAPP_URL) {
    const r = await fetch(WEBAPP_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ factories }),
    });
    if (!r.ok) throw new Error("Не удалось записать в Google-таблицу");
    return;
  }
  // SQLite fallback
  db.prepare("DELETE FROM contacts").run();
  db.prepare("DELETE FROM factories").run();
  const ins = db.prepare(
    `INSERT INTO factories (id, name, city, products, reliability, moq, lead_time, payment, certifications, notes, created_by_id, updated_by_id, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  );
  const insC = db.prepare("INSERT INTO contacts (factory_id, name, role, wechat, whatsapp, phone, email) VALUES (?,?,?,?,?,?,?)");
  for (const f of factories) {
    const createdById = f.createdBy ? db.prepare("SELECT id FROM users WHERE name = ?").get(f.createdBy)?.id ?? null : null;
    const updatedById = f.updatedBy ? db.prepare("SELECT id FROM users WHERE name = ?").get(f.updatedBy)?.id ?? null : null;
    ins.run(f.id, f.name, f.city || "", (f.products || []).join(","), f.reliability || "unknown",
      f.moq || "", f.leadTime || "", f.payment || "", f.certifications || "", f.notes || "",
      createdById, updatedById, f.createdAt || now(), f.updatedAt || now());
    for (const c of f.contacts || []) insC.run(f.id, c.name || "", c.role || "", c.wechat || "", c.whatsapp || "", c.phone || "", c.email || "");
  }
}

export function isGoogleStorage() {
  return !!WEBAPP_URL;
}