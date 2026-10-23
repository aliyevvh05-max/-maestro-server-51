require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express(); // VACİB: app burada təyin olunmalıdır

const {
  PORT = 3000, BASE_URL = `http://localhost:${PORT}`, JWT_SECRET, OPENAI_API_KEY,
  EPOINT_PUBLIC_KEY, EPOINT_PRIVATE_KEY, EPOINT_BASE_URL = 'https://epoint.az', EPOINT_CURRENCY = 'USD', EPOINT_LANGUAGE = 'en',
  OPENAI_IMAGE_MODEL = 'gpt-image-2', OPENAI_IMAGE_QUALITY = 'medium',
  FREE_CREDITS = '1', RETENTION_DAYS = '90'
} = process.env;

if (!JWT_SECRET) throw new Error('JWT_SECRET is required in .env');
const epointReady = !!(EPOINT_PUBLIC_KEY && EPOINT_PRIVATE_KEY);

/* credits packs (prices in cents) */
const PLANS = {
  starter: { name: 'Maestro Starter — 20 credits', credits: 20, cents: 900 },
  pro: { name: 'Maestro Pro — 100 credits', credits: 100, cents: 2900 },
  studio: { name: 'Maestro Studio — 500 credits', credits: 500, cents: 9900 }
};

/* storage */
const DATA = path.join(__dirname, 'data'), IMG = path.join(DATA, 'img');
fs.mkdirSync(IMG, { recursive: true });
const db = new Database(path.join(DATA, 'maestro.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pw TEXT NOT NULL, credits INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS generations (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, style TEXT, category TEXT, room TEXT, palette TEXT, prompt TEXT, before_file TEXT, after_file TEXT, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS payments (order_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, plan TEXT NOT NULL, credits INTEGER NOT NULL, cents INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', transaction_id TEXT, created INTEGER NOT NULL, paid_at INTEGER);
CREATE INDEX IF NOT EXISTS p_user ON payments(user_id);
CREATE INDEX IF NOT EXISTS g_user ON generations(user_id);
`);

/* anti-abuse columns (added once on existing databases) */
for (const col of ['email_key TEXT', 'signup_ip TEXT']) {
  try { db.exec('ALTER TABLE users ADD COLUMN ' + col); } catch (e) { /* already exists */ }
}
db.exec('CREATE INDEX IF NOT EXISTS u_ekey ON users(email_key); CREATE INDEX IF NOT EXISTS u_ip ON users(signup_ip, created);');

app.use(express.static(__dirname));
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

/* ---- Epoint helpers ---- */
const epSign = (data) => crypto.createHash('sha1').update(EPOINT_PRIVATE_KEY + data + EPOINT_PRIVATE_KEY).digest('base64');
const epPack = (obj) => { const data = Buffer.from(JSON.stringify(obj)).toString('base64'); return { data, signature: epSign(data) }; };
function epSignatureOk(data, signature) {
  const a = Buffer.from(epSign(String(data || ''))), b = Buffer.from(String(signature || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* Epoint result callback */
app.post('/api/epoint-callback', express.urlencoded({ extended: false, limit: '64kb' }), (req, res) => {
  if (!epointReady) return res.status(503).end();
  const { data, signature } = req.body || {};
  if (!epSignatureOk(data, signature)) { console.warn('epoint callback: bad signature'); return res.status(400).send('Bad signature'); }
  let r;
  try { r = JSON.parse(Buffer.from(String(data), 'base64').toString('utf8')); } catch (e) { return res.status(400).send('Bad data'); }
  console.log('epoint callback', JSON.stringify({ order_id: r.order_id, status: r.status, transaction: r.transaction, code: r.code }));
  const pay = db.prepare('SELECT * FROM payments WHERE order_id = ?').get(String(r.order_id || ''));
  if (!pay) return res.status(200).send('OK');
  if (r.status === 'success') {
    if (r.amount !== undefined && Math.abs(Number(r.amount) - pay.cents / 100) > 0.005) { console.warn('epoint callback: amount mismatch', r.order_id); return res.status(200).send('OK'); }
    if (r.currency && String(r.currency).toUpperCase() !== EPOINT_CURRENCY.toUpperCase()) { console.warn('epoint callback: currency mismatch', r.order_id); return res.status(200).send('OK'); }
    db.transaction(() => {
      const up = db.prepare("UPDATE payments SET status = 'paid', transaction_id = ?, paid_at = ? WHERE order_id = ? AND status = 'pending'")
        .run(String(r.transaction || ''), Date.now(), pay.order_id);
      if (up.changes) db.prepare('UPDATE users SET credits = credits + ? WHERE id = ?').run(pay.credits, pay.user_id);
    })();
  } else {
    db.prepare("UPDATE payments SET status = 'failed' WHERE order_id = ? AND status = 'pending'").run(pay.order_id);
  }
  res.status(200).send('OK');
});

app.use(express.json({ limit: '16mb' }));
app.use(cookieParser());

/* ---- auth helpers ---- */
const publicUser = (u) => ({ name: u.name, email: u.email, credits: u.credits });
function setSession(res, id) {
  const token = jwt.sign({ id }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('maestro', token, { httpOnly: true, sameSite: 'lax', secure: BASE_URL.startsWith('https'), maxAge: 30 * 864e5 });
}
function auth(req, res, next) {
  try {
    const { id } = jwt.verify(req.cookies.maestro, JWT_SECRET);
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!u) throw 0;
    req.user = u; next();
  } catch (e) { res.status(401).json({ error: 'Please sign in' }); }
}
const authLimit = rateLimit({ windowMs: 15 * 60e3, max: 30, standardHeaders: true });
const genLimit = rateLimit({ windowMs: 60e3, max: 6, standardHeaders: true, message: { error: 'Too many renders, slow down' } });

app.get('/api/health', (_req, res) => res.json({ ok: true, ai: !!OPENAI_API_KEY, payments: epointReady }));

function emailKey(em) {
  let [local, domain] = em.split('@');
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (domain === 'gmail.com') local = local.split('+')[0].replace(/\./g, '');
  else local = local.split('+')[0];
  return local + '@' + domain;
}
const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org', 'yopmail.com', 'trashmail.com', 'throwawaymail.com', 'sharklasers.com', 'getnada.com', 'dispostable.com', 'maildrop.cc']);
const signupLimit = rateLimit({ windowMs: 24 * 3600e3, max: 5, standardHeaders: true, message: { error: 'Too many sign-ups from this network. Try again tomorrow.' } });

app.post('/api/signup', authLimit, signupLimit, async (req, res) => {
  const { name, email, password } = req.body || {};
  const em = String(email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return res.status(400).json({ error: 'Invalid email' });
  if (DISPOSABLE.has(em.split('@')[1])) return res.status(400).json({ error: 'Please use a permanent email address' });
  if (String(password || '').length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const nm = String(name || '').trim().slice(0, 80);
  if (!nm) return res.status(400).json({ error: 'Name is required' });
  const ek = emailKey(em);
  if (db.prepare('SELECT 1 FROM users WHERE email = ? OR email_key = ?').get(em, ek)) return res.status(409).json({ error: 'This email is already registered' });
  
  const recent = db.prepare('SELECT COUNT(*) AS n FROM users WHERE signup_ip = ? AND created > ?').get(req.ip, Date.now() - 30 * 864e5).n;
  const free = recent < 2 ? (parseInt(FREE_CREDITS, 10) || 0) : 0;
  const r = db.prepare('INSERT INTO users (email, name, pw, credits, created, email_key, signup_ip) VALUES (?,?,?,?,?,?,?)')
    .run(em, nm, await bcrypt.hash(password, 11), free, Date.now(), ek, req.ip);
  setSession(res, r.lastInsertRowid);
  res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(r.lastInsertRowid)) });
});

app.post('/api/login', authLimit, async (req, res) => {
  const em = String((req.body || {}).email || '').trim().toLowerCase();
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(em);
  if (!u || !(await bcrypt.compare(String((req.body || {}).password || ''), u.pw))) return res.status(401).json({ error: 'Wrong email or password' });
  setSession(res, u.id);
  res.json({ user: publicUser(u) });
});

app.post('/api/logout', (_req, res) => { res.clearCookie('maestro'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

/* ---- gallery ---- */
app.get('/api/generations', auth, (req, res) => {
  const generations = db.prepare('SELECT * FROM generations WHERE user_id = ? ORDER BY created DESC').all(req.user.id)
    .map((g) => ({ id: g.id, style: g.style, cat: g.category, provider: 'AI', before: '/img/' + g.before_file, after: '/img/' + g.after_file, ts: g.created }));
  const orders = db.prepare("SELECT * FROM payments WHERE user_id = ? AND status = 'paid' ORDER BY created DESC").all(req.user.id)
    .map((o) => ({ plan: o.plan, credits: o.credits, amount: o.cents / 100, mode: 'epoint', ts: o.paid_at || o.created }));
  res.json({ generations, orders });
});

app.delete('/api/generations/:id', auth, (req, res) => {
  const g = db.prepare('SELECT * FROM generations WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (g) { [g.before_file, g.after_file].forEach((f) => fs.unlink(path.join(IMG, f), () => {})); db.prepare('DELETE FROM generations WHERE id = ?').run(g.id); }
  res.json({ ok: true });
});

app.use('/img', express.static(IMG, { maxAge: '7d', index: false }));

/* ---- AI render ---- */
const clip = (v, n) => String(v || '').replace(/[\r\n]+/g, ' ').slice(0, n);
app.post('/api/generate', auth, genLimit, async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(503).json({ error: 'AI engine is not configured' });
  const b = req.body || {};
  const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(String(b.image || ''));
  if (!m) return res.status(400).json({ error: 'Invalid image' });
  const debit = db.prepare('UPDATE users SET credits = credits - 1 WHERE id = ? AND credits >= 1').run(req.user.id);
  if (!debit.changes) return res.status(402).json({ error: 'No credits left — please buy a pack' });
  try {
    const buf = Buffer.from(m[2], 'base64');
    if (buf.length > 10e6) throw new Error('Image too large');
    const style = clip(b.style, 60), cat = clip(b.category, 60), room = clip(b.room, 30) || 'room', pal = clip(b.palette, 20);
    const prompt = `Redesign this ${room.toLowerCase()} in ${style} interior design style (${cat}): ${clip(b.description, 200)}. ` +
      (pal && pal !== 'Auto' ? `${pal} color palette. ` : '') +
      'Keep the exact room architecture, walls, windows, doors and camera perspective. Replace furniture, materials, lighting and decor. Photorealistic architectural photography, natural light, high detail.' +
      (b.custom ? ` Additional wishes: ${clip(b.custom, 300)}` : '');
    const fd = new FormData();
    fd.append('model', OPENAI_IMAGE_MODEL);
    fd.append('image', new Blob([buf], { type: 'image/' + m[1] }), 'room.' + (m[1] === 'jpeg' ? 'jpg' : m[1]));
    fd.append('prompt', prompt); fd.append('size', 'auto'); fd.append('quality', OPENAI_IMAGE_QUALITY);
    const r = await fetch('https://api.openai.com/v1/images/edits', { method: 'POST', headers: { Authorization: 'Bearer ' + OPENAI_API_KEY }, body: fd });
    const j = await r.json();
    if (!r.ok) throw new Error((j.error && j.error.message) || 'AI error');
    const id = crypto.randomBytes(12).toString('hex');
    const bf = id + '-b.' + (m[1] === 'jpeg' ? 'jpg' : m[1]), af = id + '-a.png';
    fs.writeFileSync(path.join(IMG, bf), buf);
    fs.writeFileSync(path.join(IMG, af), Buffer.from(j.data[0].b64_json, 'base64'));
    db.prepare('INSERT INTO generations (id, user_id, style, category, room, palette, prompt, before_file, after_file, created) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .run(id, req.user.id, style, cat, room, pal, prompt, bf, af, Date.now());
    res.json({ image: '/img/' + af, credits: db.prepare('SELECT credits FROM users WHERE id = ?').get(req.user.id).credits });
  } catch (e) {
    console.error('generate failed:', e.message);
    db.prepare('UPDATE users SET credits = credits + 1 WHERE id = ?').run(req.user.id);
    res.status(502).json({ error: 'Render failed — your credit was refunded. Try again.' });
  }
});

/* ---- payments: Epoint ---- */
app.post('/api/checkout', auth, async (req, res) => {
  if (!epointReady) return res.status(503).json({ error: 'Payments are not configured' });
  const plan = (req.body || {}).plan, p = PLANS[plan];
  if (!p) return res.status(400).json({ error: 'Unknown plan' });
  const orderId = 'M' + Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
  db.prepare('INSERT INTO payments (order_id, user_id, plan, credits, cents, created) VALUES (?,?,?,?,?,?)')
    .run(orderId, req.user.id, plan, p.credits, p.cents, Date.now());
  try {
    const body = epPack({
      public_key: EPOINT_PUBLIC_KEY, amount: (p.cents / 100).toFixed(2), currency: EPOINT_CURRENCY, language: EPOINT_LANGUAGE,
      order_id: orderId, description: p.name,
      success_redirect_url: BASE_URL + '/?paid=1', error_redirect_url: BASE_URL + '/?paid=0',
      result_url: BASE_URL + '/api/epoint-callback'
    });
    const r = await fetch(EPOINT_BASE_URL + '/api/1/request', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
    const j = await r.json();
    if (!r.ok || j.status !== 'success' || !j.redirect_url) throw new Error('Epoint: ' + JSON.stringify(j).slice(0, 300));
    res.json({ url: j.redirect_url });
  } catch (e) {
    console.error('checkout failed:', e.message);
    db.prepare("UPDATE payments SET status = 'failed' WHERE order_id = ? AND status = 'pending'").run(orderId);
    res.status(502).json({ error: 'Could not start checkout' });
  }
});

/* ---- housekeeping ---- */
function cleanup() {
  const days = parseInt(RETENTION_DAYS, 10);
  if (!days) return;
  const old = db.prepare('SELECT * FROM generations WHERE created < ?').all(Date.now() - days * 864e5);
  for (const g of old) { [g.before_file, g.after_file].forEach((f) => fs.unlink(path.join(IMG, f), () => {})); db.prepare('DELETE FROM generations WHERE id = ?').run(g.id); }
  if (old.length) console.log(`cleanup: removed ${old.length} renders older than ${days} days`);
}
cleanup(); setInterval(cleanup, 24 * 3600e3);

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.listen(PORT, () => console.log(`MAESTRO running on ${BASE_URL}`));
