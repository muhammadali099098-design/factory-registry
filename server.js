import express from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { fetchAll, savePatch } from "./sheet-store.js";

const app = express();
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const SESSION_COOKIE = "registry_session";
const SESSION_DAYS = 30;

// ---------- Сессии (в памяти; при перезапуске сотрудники входят заново) ----------
const sessions = new Map(); // token -> { userId, expiresAt }

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
  const expiresAt = Date.now() + SESSION_DAYS * 24 * 3600 * 1000;
  sessions.set(token, { userId, expiresAt });
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${token}; HttpOnly; Path=/; Max-Age=${SESSION_DAYS * 24 * 3600}; SameSite=Lax`);
}
function destroySession(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}
async function currentUser(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  const sess = token ? sessions.get(token) : null;
  if (!sess || sess.expiresAt < Date.now()) return null;
  const data = await fetchAll();
  const user = (data.users || []).find((u) => Number(u.id) === sess.userId);
  return user ? { id: Number(user.id), name: user.name, email: user.email, role: user.role } : null;
}
function requireAuth(req, res, next) {
  currentUser(req).then((user) => {
    if (!user) return res.status(401).json({ error: "Требуется вход" });
    req.user = user;
    next();
  }).catch((e) => res.status(500).json({ error: e.message }));
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Нет прав администратора" });
  next();
}

// ---------- Утилиты ----------
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
function nextId(list) { return list.reduce((m, f) => Math.max(m, Number(f.id) || 0), 0) + 1; }

async function log(user, action, factoryId, factoryName, detail = "") {
  const data = await fetchAll();
  const audit = data.audit || [];
  audit.push({
    id: nextId(audit), user_id: user ? user.id : null, user_name: user ? user.name : null,
    action, factory_id: factoryId, factory_name: factoryName, detail: detail || "", created_at: now(),
  });
  await savePatch({ audit });
}

// ---------- Аутентификация ----------
app.post("/api/auth/register", async (req, res) => {
  try {
    const data = await fetchAll();
    if ((data.users || []).length > 0) return res.status(403).json({ error: "Реестр уже создан. Доступ выдаёт администратор." });
    const { name, email, password } = req.body || {};
    if (!name?.trim() || !email?.trim() || !password || String(password).length < 6) return res.status(400).json({ error: "Заполните имя, email и пароль (мин. 6 символов)" });
    const exists = (data.users || []).some((u) => u.email === String(email).trim().toLowerCase());
    if (exists) return res.status(400).json({ error: "Email уже занят" });
    const user = { id: nextId(data.users || []), name: name.trim(), email: String(email).trim().toLowerCase(), password_hash: bcrypt.hashSync(String(password), 10), role: "admin", created_at: now() };
    await savePatch({ users: [...(data.users || []), user] });
    createSession(res, user.id);
    res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const data = await fetchAll();
    const user = (data.users || []).find((u) => u.email === String(email || "").trim().toLowerCase());
    if (!user || !bcrypt.compareSync(String(password || ""), user.password_hash)) return res.status(401).json({ error: "Неверный email или пароль" });
    createSession(res, user.id);
    res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/auth/logout", (req, res) => { destroySession(req, res); res.json({ ok: true }); });
app.get("/api/auth/me", async (req, res) => { const user = await currentUser(req); res.json({ user }); });

// ---------- Пользователи (админ) ----------
app.get("/api/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const data = await fetchAll();
    res.json({ users: (data.users || []).map((u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, created_at: u.created_at })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name?.trim() || !email?.trim() || !password || String(password).length < 6) return res.status(400).json({ error: "Заполните имя, email и пароль (мин. 6 символов)" });
    const data = await fetchAll();
    const users = data.users || [];
    if (users.some((u) => u.email === String(email).trim().toLowerCase())) return res.status(400).json({ error: "Такой email уже есть" });
    const user = { id: nextId(users), name: name.trim(), email: String(email).trim().toLowerCase(), password_hash: bcrypt.hashSync(String(password), 10), role: "member", created_at: now() };
    await savePatch({ users: [...users, user] });
    res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { role } = req.body || {};
    if (!["admin", "member"].includes(role)) return res.status(400).json({ error: "Неверная роль" });
    const data = await fetchAll();
    const users = data.users || [];
    const target = users.find((u) => Number(u.id) === id);
    if (!target) return res.status(404).json({ error: "Пользователь не найден" });
    if (target.role === "admin" && role === "member" && users.filter((u) => u.role === "admin").length <= 1) return res.status(400).json({ error: "Нельзя убрать последнего администратора" });
    target.role = role;
    await savePatch({ users });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const data = await fetchAll();
    const users = data.users || [];
    const target = users.find((u) => Number(u.id) === id);
    if (!target) return res.status(404).json({ error: "Пользователь не найден" });
    if (target.id === req.user.id) return res.status(400).json({ error: "Нельзя удалить самого себя" });
    if (target.role === "admin" && users.filter((u) => u.role === "admin").length <= 1) return res.status(400).json({ error: "Нельзя удалить последнего администратора" });
    await savePatch({ users: users.filter((u) => Number(u.id) !== id) });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch("/api/users/:id/password", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { password } = req.body || {};
    if (!password || String(password).length < 6) return res.status(400).json({ error: "Пароль должен быть не короче 6 символов" });
    const data = await fetchAll();
    const users = data.users || [];
    const target = users.find((u) => Number(u.id) === id);
    if (!target) return res.status(404).json({ error: "Пользователь не найден" });
    target.password_hash = bcrypt.hashSync(String(password), 10);
    await savePatch({ users });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Настройки ----------
app.get("/api/settings", async (req, res) => {
  try {
    const data = await fetchAll();
    const get = (k, d) => (data.settings || []).find((s) => s.key === k)?.value ?? d;
    res.json({ title: get("title", "Реестр заводов"), color: get("color", "#d7151f") });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put("/api/settings", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { title, color } = req.body || {};
    const data = await fetchAll();
    let settings = data.settings || [];
    const set = (k, v) => {
      if (typeof v !== "string") return;
      const ex = settings.find((s) => s.key === k);
      if (ex) ex.value = v; else settings.push({ key: k, value: v });
    };
    if (title !== undefined) set("title", String(title).slice(0, 80));
    if (color !== undefined && /^#[0-9a-fA-F]{6}$/.test(color)) set("color", color);
    await savePatch({ settings });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Заводы ----------
app.get("/api/factories", requireAuth, async (req, res) => {
  try {
    const { search = "", reliability = "", product = "" } = req.query;
    const data = await fetchAll();
    let fs = data.factories || [];
    if (search) {
      const q = String(search).toLowerCase();
      fs = fs.filter((f) => f.name.toLowerCase().includes(q) || (f.city || "").toLowerCase().includes(q) || (f.products || []).some((p) => p.toLowerCase().includes(q)));
    }
    if (reliability) fs = fs.filter((f) => f.reliability === reliability);
    if (product) fs = fs.filter((f) => (f.products || []).some((p) => p.toLowerCase() === String(product).toLowerCase()));
    fs.sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")));
    res.json({ factories: fs });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get("/api/factories/:id", requireAuth, async (req, res) => {
  try {
    const data = await fetchAll();
    const f = (data.factories || []).find((x) => Number(x.id) === Number(req.params.id));
    if (!f) return res.status(404).json({ error: "Не найдено" });
    res.json({ factory: f });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/factories", requireAuth, async (req, res) => {
  try {
    const v = validateFactory(req.body);
    if (v.error) return res.status(400).json({ error: v.error });
    const f = v.value;
    const data = await fetchAll();
    const fs = data.factories || [];
    const force = !!req.body.force;
    if (!force) {
      const dups = findDuplicates(fs, f.name);
      if (dups.length) return res.status(409).json({ error: "Похожий завод уже существует", duplicates: dups });
    }
    const created = { id: nextId(fs), ...f, createdBy: req.user.name, updatedBy: req.user.name, createdAt: now(), updatedAt: now() };
    await savePatch({ factories: [...fs, created] });
    await log(req.user, "create", created.id, f.name);
    res.json({ factory: created });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put("/api/factories/:id", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const v = validateFactory(req.body);
    if (v.error) return res.status(400).json({ error: v.error });
    const f = v.value;
    const data = await fetchAll();
    const fs = data.factories || [];
    const idx = fs.findIndex((x) => Number(x.id) === id);
    if (idx === -1) return res.status(404).json({ error: "Не найдено" });
    const force = !!req.body.force;
    if (!force) {
      const dups = findDuplicates(fs, f.name, id);
      if (dups.length) return res.status(409).json({ error: "Похожий завод уже существует", duplicates: dups });
    }
    fs[idx] = { ...fs[idx], ...f, updatedBy: req.user.name, updatedAt: now() };
    await savePatch({ factories: fs });
    await log(req.user, "update", id, f.name);
    res.json({ factory: fs[idx] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete("/api/factories/:id", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const data = await fetchAll();
    const fs = data.factories || [];
    const target = fs.find((x) => Number(x.id) === id);
    if (!target) return res.status(404).json({ error: "Не найдено" });
    await savePatch({ factories: fs.filter((x) => Number(x.id) !== id) });
    await log(req.user, "delete", id, target.name);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/factories/:id/merge", requireAuth, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    const fromId = Number(req.body.fromId);
    const data = await fetchAll();
    const fs = data.factories || [];
    const target = fs.find((x) => Number(x.id) === targetId);
    const from = fs.find((x) => Number(x.id) === fromId);
    if (!target || !from) return res.status(404).json({ error: "Завод не найден" });
    const moved = (from.contacts || []).map((c) => ({ ...c }));
    target.contacts = [...(target.contacts || []), ...moved];
    target.updatedBy = req.user.name;
    target.updatedAt = now();
    await savePatch({ factories: fs.filter((x) => Number(x.id) !== fromId) });
    await log(req.user, "merge", targetId, target.name, `Объединено с «${from.name}» (${moved.length} контакта)`);
    res.json({ factory: target });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Журнал ----------
app.get("/api/audit", requireAuth, async (req, res) => {
  try {
    const data = await fetchAll();
    const audit = (data.audit || []).slice().sort((a, b) => Number(b.id) - Number(a.id)).slice(0, 200);
    res.json({ entries: audit });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Категории
app.get("/api/tags", requireAuth, async (req, res) => {
  try {
    const data = await fetchAll();
    const set = new Set();
    for (const f of data.factories || []) for (const p of f.products || []) { const t = p.trim(); if (t) set.add(t); }
    res.json({ tags: Array.from(set).sort((a, b) => a.localeCompare(b, "ru")) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Экспорт в Excel (.xls) ----------
app.get("/api/export", requireAuth, async (req, res) => {
  try {
    const data = await fetchAll();
    const fs = data.factories || [];
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