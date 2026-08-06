import express from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import db from "./db.js";
import { listFactories, replaceAll } from "./store.js";

const app = express();
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const SESSION_COOKIE = "registry_session";
const SESSION_DAYS = 30;

// ---------- Сессии ----------
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 3600 * 1000);
  db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)").run(token, userId, expires.toISOString());
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${token}; HttpOnly; Path=/; Max-Age=${SESSION_DAYS * 24 * 3600}; SameSite=Lax`);
}
function destroySession(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (token) db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}
function currentUser(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  return db.prepare(
    `SELECT u.id, u.name, u.email, u.role FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > ?`,
  ).get(token, new Date().toISOString()) || null;
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Требуется вход" });
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Нет прав администратора" });
  next();
}

// ---------- Журнал действий (SQLite) ----------
function log(user, action, factoryId, factoryName, detail = "") {
  db.prepare("INSERT INTO audit_log (user_id, user_name, action, factory_id, factory_name, detail) VALUES (?,?,?,?,?,?)")
    .run(user ? user.id : null, user ? user.name : null, action, factoryId, factoryName, detail);
}

// ---------- Утилиты заводов ----------
function now() { return new Date().toISOString().slice(0, 19).replace("T", " "); }
function normalizeName(s) { return String(s || "").toLowerCase().replace(/[^a-zа-яё0-9]/gi, ""); }
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[m][n];
}
function findDuplicates(factories, name, excludeId) {
  const norm = normalizeName(name);
  if (!norm) return [];
  const out = [];
  for (const r of factories) {
    if (excludeId && r.id === excludeId) continue;
    const n = normalizeName(r.name);
    if (!n) continue;
    const exact = n === norm;
    const contains = n.includes(norm) || norm.includes(n);
    const lev = levenshtein(n, norm);
    const threshold = n.length <= 4 ? 1 : 2;
    if (exact || contains || lev <= threshold) {
      out.push({ id: r.id, name: r.name, city: r.city, products: (r.products || []).join(", "), contactsCount: (r.contacts || []).length });
    }
  }
  return out;
}
function normContact(c) {
  const s = (v) => String(v || "").trim();
  return { name: s(c.name), role: s(c.role), wechat: s(c.wechat), whatsapp: s(c.whatsapp), phone: s(c.phone), email: s(c.email) };
}
function validateFactory(b) {
  if (!b || typeof b.name !== "string" || !b.name.trim()) return { error: "Укажите название завода" };
  const contacts = Array.isArray(b.contacts) ? b.contacts.map(normContact).filter((c) => c.name || c.wechat || c.whatsapp || c.phone || c.email) : [];
  return {
    value: {
      name: b.name.trim(),
      city: (b.city || "").trim(),
      products: Array.isArray(b.products) ? b.products.map((p) => String(p).trim()).filter(Boolean) : [],
      reliability: ["reliable", "issues", "unknown"].includes(b.reliability) ? b.reliability : "unknown",
      moq: (b.moq || "").trim(),
      leadTime: (b.leadTime || "").trim(),
      payment: (b.payment || "").trim(),
      certifications: (b.certifications || "").trim(),
      notes: (b.notes || "").trim(),
      contacts,
    },
  };
}
function nextId(factories) {
  return factories.reduce((m, f) => Math.max(m, Number(f.id) || 0), 0) + 1;
}

// ---------- Аутентификация ----------
app.post("/api/auth/register", (req, res) => {
  const count = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
  if (count > 0) return res.status(403).json({ error: "Реестр уже создан. Доступ выдаёт администратор." });
  const { name, email, password } = req.body || {};
  if (!name?.trim() || !email?.trim() || !password || String(password).length < 6) return res.status(400).json({ error: "Заполните имя, email и пароль (мин. 6 символов)" });
  const hash = bcrypt.hashSync(String(password), 10);
  try {
    const info = db.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,'admin')").run(name.trim(), email.trim().toLowerCase(), hash);
    const user = db.prepare("SELECT id,name,email,role FROM users WHERE id = ?").get(info.lastInsertRowid);
    createSession(res, user.id);
    return res.json({ user });
  } catch { return res.status(400).json({ error: "Email уже занят" }); }
});
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(String(email || "").trim().toLowerCase());
  if (!user || !bcrypt.compareSync(String(password || ""), user.password_hash)) return res.status(401).json({ error: "Неверный email или пароль" });
  createSession(res, user.id);
  return res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});
app.post("/api/auth/logout", (req, res) => { destroySession(req, res); res.json({ ok: true }); });
app.get("/api/auth/me", (req, res) => { const user = currentUser(req); res.json({ user }); });

// ---------- Пользователи (админ, SQLite) ----------
app.get("/api/users", requireAuth, requireAdmin, (req, res) => {
  res.json({ users: db.prepare("SELECT id, name, email, role, created_at FROM users ORDER BY role, name").all() });
});
app.post("/api/users", requireAuth, requireAdmin, (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name?.trim() || !email?.trim() || !password || String(password).length < 6) return res.status(400).json({ error: "Заполните имя, email и пароль (мин. 6 символов)" });
  try {
    const info = db.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,'member')").run(name.trim(), email.trim().toLowerCase(), bcrypt.hashSync(String(password), 10));
    res.json({ user: db.prepare("SELECT id,name,email,role FROM users WHERE id = ?").get(info.lastInsertRowid) });
  } catch { return res.status(400).json({ error: "Такой email уже есть" }); }
});
app.patch("/api/users/:id", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { role } = req.body || {};
  if (!["admin", "member"].includes(role)) return res.status(400).json({ error: "Неверная роль" });
  const target = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  if (!target) return res.status(404).json({ error: "Пользователь не найден" });
  if (target.role === "admin" && role === "member") {
    if (db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='admin'").get().c <= 1) return res.status(400).json({ error: "Нельзя убрать последнего администратора" });
  }
  db.prepare("UPDATE users SET role = ? WHERE id = ?").run(role, id);
  res.json({ ok: true });
});
app.delete("/api/users/:id", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const target = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  if (!target) return res.status(404).json({ error: "Пользователь не найден" });
  if (target.id === req.user.id) return res.status(400).json({ error: "Нельзя удалить самого себя" });
  if (target.role === "admin" && db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='admin'").get().c <= 1) return res.status(400).json({ error: "Нельзя удалить последнего администратора" });
  db.prepare("DELETE FROM users WHERE id = ?").run(id);
  res.json({ ok: true });
});
app.patch("/api/users/:id/password", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { password } = req.body || {};
  if (!password || String(password).length < 6) return res.status(400).json({ error: "Пароль должен быть не короче 6 символов" });
  const target = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  if (!target) return res.status(404).json({ error: "Пользователь не найден" });
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(bcrypt.hashSync(String(password), 10), id);
  res.json({ ok: true });
});

// ---------- Настройки ----------
app.get("/api/settings", (req, res) => {
  const get = (k, d) => db.prepare("SELECT value FROM settings WHERE key = ?").get(k)?.value ?? d;
  res.json({ title: get("title", "Реестр заводов"), color: get("color", "#d7151f") });
});
app.put("/api/settings", requireAuth, requireAdmin, (req, res) => {
  const { title, color } = req.body || {};
  const set = (k, v) => { if (typeof v !== "string") return; db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(k, v); };
  if (title !== undefined) set("title", String(title).slice(0, 80));
  if (color !== undefined && /^#[0-9a-fA-F]{6}$/.test(color)) set("color", color);
  res.json({ ok: true });
});

// ---------- Заводы (Google-таблица / SQLite) ----------
app.get("/api/factories", requireAuth, async (req, res) => {
  try {
    const { search = "", reliability = "", product = "" } = req.query;
    let fs = await listFactories();
    if (search) {
      const q = String(search).toLowerCase();
      fs = fs.filter((f) =>
        f.name.toLowerCase().includes(q) ||
        (f.city || "").toLowerCase().includes(q) ||
        (f.products || []).some((p) => p.toLowerCase().includes(q)),
      );
    }
    if (reliability) fs = fs.filter((f) => f.reliability === reliability);
    if (product) fs = fs.filter((f) => (f.products || []).some((p) => p.toLowerCase() === String(product).toLowerCase()));
    fs.sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")));
    res.json({ factories: fs });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get("/api/factories/:id", requireAuth, async (req, res) => {
  try {
    const fs = await listFactories();
    const f = fs.find((x) => Number(x.id) === Number(req.params.id));
    if (!f) return res.status(404).json({ error: "Не найдено" });
    res.json({ factory: f });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/factories", requireAuth, async (req, res) => {
  try {
    const v = validateFactory(req.body);
    if (v.error) return res.status(400).json({ error: v.error });
    const f = v.value;
    const fs = await listFactories();
    const force = !!req.body.force;
    if (!force) {
      const dups = findDuplicates(fs, f.name);
      if (dups.length) return res.status(409).json({ error: "Похожий завод уже существует", duplicates: dups });
    }
    const id = nextId(fs);
    const created = {
      id, ...f,
      createdBy: req.user.name, updatedBy: req.user.name,
      createdAt: now(), updatedAt: now(),
    };
    await replaceAll([...fs, created]);
    log(req.user, "create", id, f.name);
    res.json({ factory: created });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put("/api/factories/:id", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const v = validateFactory(req.body);
    if (v.error) return res.status(400).json({ error: v.error });
    const f = v.value;
    const fs = await listFactories();
    const idx = fs.findIndex((x) => Number(x.id) === id);
    if (idx === -1) return res.status(404).json({ error: "Не найдено" });
    const force = !!req.body.force;
    if (!force) {
      const dups = findDuplicates(fs, f.name, id);
      if (dups.length) return res.status(409).json({ error: "Похожий завод уже существует", duplicates: dups });
    }
    const updated = { ...fs[idx], ...f, updatedBy: req.user.name, updatedAt: now() };
    fs[idx] = updated;
    await replaceAll(fs);
    log(req.user, "update", id, f.name);
    res.json({ factory: updated });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete("/api/factories/:id", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const fs = await listFactories();
    const target = fs.find((x) => Number(x.id) === id);
    if (!target) return res.status(404).json({ error: "Не найдено" });
    await replaceAll(fs.filter((x) => Number(x.id) !== id));
    log(req.user, "delete", id, target.name);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/factories/:id/merge", requireAuth, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    const fromId = Number(req.body.fromId);
    const fs = await listFactories();
    const target = fs.find((x) => Number(x.id) === targetId);
    const from = fs.find((x) => Number(x.id) === fromId);
    if (!target || !from) return res.status(404).json({ error: "Завод не найден" });
    const moved = (from.contacts || []).map((c) => ({ ...c }));
    target.contacts = [...(target.contacts || []), ...moved];
    target.updatedBy = req.user.name;
    target.updatedAt = now();
    await replaceAll(fs.filter((x) => Number(x.id) !== fromId));
    log(req.user, "merge", targetId, target.name, `Объединено с «${from.name}» (${moved.length} контакта)`);
    res.json({ factory: target });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Журнал ----------
app.get("/api/audit", requireAuth, (req, res) => {
  res.json({ entries: db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").all() });
});
// Категории
app.get("/api/tags", requireAuth, async (req, res) => {
  try {
    const set = new Set();
    for (const f of await listFactories()) for (const p of f.products || []) { const t = p.trim(); if (t) set.add(t); }
    res.json({ tags: Array.from(set).sort((a, b) => a.localeCompare(b, "ru")) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Экспорт в Excel (.xls) ----------
app.get("/api/export", requireAuth, async (req, res) => {
  try {
    const fs = await listFactories();
    const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    const cell = (v) => `<Cell><Data ss:Type="String">${esc(v)}</Data></Cell>`;
    const relL = { reliable: "Надёжный", issues: "Есть проблемы", unknown: "Не оценено" };
    const cols = ["Название","Город","Продукция","Надёжность","Контакты","MOQ","Сроки","Оплата","Сертификаты","Примечания","Добавил","Изменил","Добавлен","Обновлён"];
    const header = `<Row>${cols.map(cell).join("")}</Row>`;
    const body = fs.map((f) => {
      const contactText = (f.contacts || []).map((c) => [c.name, c.role && `(${c.role})`, c.wechat && `WeChat: ${c.wechat}`, c.whatsapp && `WA: ${c.whatsapp}`, c.phone, c.email].filter(Boolean).join(" | ")).join("\n");
      return `<Row>${[f.name, f.city, (f.products || []).join(", "), relL[f.reliability] || f.reliability, contactText, f.moq, f.leadTime, f.payment, f.certifications, f.notes, f.createdBy, f.updatedBy, f.createdAt, f.updatedAt].map(cell).join("")}</Row>`;
    }).join("");
    const xml = `<?xml version="1.0"?><?mso-application progid="Excel.Sheet"?><Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"><Worksheet ss:Name="Заводы"><Table>${header}${body}</Table></Worksheet></Workbook>`;
    res.setHeader("Content-Type", "application/vnd.ms-excel;charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="zavody.xls"`);
    res.send("\ufeff" + xml);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Статика ----------
app.use(express.static("public"));
app.listen(PORT, () => console.log(`Реестр запущен: http://localhost:${PORT}`));