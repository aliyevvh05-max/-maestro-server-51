// Maestro AI Server - Production Ready
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
const {
  PORT = 3000, BASE_URL = `http://localhost:${PORT}`, JWT_SECRET, OPENAI_API_KEY,
  EPOINT_PUBLIC_KEY, EPOINT_PRIVATE_KEY, EPOINT_BASE_URL = 'https://epoint.az', EPOINT_CURRENCY = 'USD', EPOINT_LANGUAGE = 'en',
  OPENAI_IMAGE_MODEL = 'gpt-image-2', OPENAI_IMAGE_QUALITY = 'medium',
  FREE_CREDITS = '1', RETENTION_DAYS = '90'
} = process.env;

const epointReady = !!(EPOINT_PUBLIC_KEY && EPOINT_PRIVATE_KEY);

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(__dirname));
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// Support & Health Check Endpoints
app.get('/api/health', (_req, res) => res.json({ ok: true, ai: !!OPENAI_API_KEY, payments: epointReady, author: 'V. Aliyev' }));

// Anti-abuse & Gmail dot/tag filtering
function emailKey(em) {
  let [local, domain] = String(em || '').split('@');
  if (!local || !domain) return em;
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (domain === 'gmail.com') local = local.replace(/\./g, '').split('+')[0];
  return `${local}@${domain}`;
}

const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org', 'yopmail.com', 'trashmail.com', 'throwawaymail.com', 'sharklasers.com', 'getnada.com', 'dispostable.com', 'maildrop.cc']);
const signupLimit = rateLimit({ windowMs: 24 * 3600e3, max: 5, standardHeaders: true, message: { error: 'Too many sign-ups from this network. Try again tomorrow.' } });
const authLimit = rateLimit({ windowMs: 15 * 60e3, max: 20 });
const genLimit = rateLimit({ windowMs: 60e3, max: 6, standardHeaders: true, message: { error: 'Too many generations. Please wait a minute.' } });

// Footer imza və dəstək məlumatı üçün xüsusi endpoint
app.get('/api/meta', (_req, res) => {
  res.json({
    appName: 'Maestro AI',
    domain: 'maestroai.design',
    supportEmail: 'support@maestroai.design',
    author: 'Created by V. Aliyev'
  });
});

const PORT_FINAL = process.env.PORT || 3000;
// Database & Session Handling
const DB_FILE = path.join(__dirname, 'database.json');
function readDb() {
  try {
    if (!fs.existsSync(DB_FILE)) return { users: {}, generations: {} };
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    return { users: {}, generations: {} };
  }
}
function writeDb(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// 1. Signup (Kayıt Ol)
app.post('/api/signup', signupLimit, (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    
    const normEmail = emailKey(email);
    const domain = normEmail.split('@')[1];
    if (DISPOSABLE.has(domain)) {
      return res.status(400).json({ error: 'Disposable email addresses are not allowed.' });
    }

    const db = readDb();
    if (db.users[normEmail]) {
      return res.status(400).json({ error: 'User already exists. Please sign in.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');

    db.users[normEmail] = {
      email: normEmail,
      passwordHash: `${salt}:${hash}`,
      credits: parseInt(FREE_CREDITS, 10) || 3,
      createdAt: Date.now()
    };
    writeDb(db);

    res.cookie('maestro_session', normEmail, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 30 * 24 * 3600e3 });
    res.json({ ok: true, user: { email: normEmail, credits: db.users[normEmail].credits } });
  } catch (err) {
    res.status(500).json({ error: 'Server error during signup' });
  }
});

// 2. Login (Giriş Yap)
app.post('/api/login', authLimit, (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const normEmail = emailKey(email);
    const db = readDb();
    const user = db.users[normEmail];
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const [salt, key] = user.passwordHash.split(':');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    if (hash !== key) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    res.cookie('maestro_session', normEmail, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 30 * 24 * 3600e3 });
    res.json({ ok: true, user: { email: normEmail, credits: user.credits } });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

// 3. Current User Check (Mevcut Kullanıcı Durumu)
app.get('/api/me', (req, res) => {
  try {
    const sessionEmail = req.cookies.maestro_session;
    if (!sessionEmail) return res.json({ user: null });

    const db = readDb();
    const user = db.users[sessionEmail];
    if (!user) return res.json({ user: null });

    res.json({ user: { email: user.email, credits: user.credits } });
  } catch {
    res.json({ user: null });
  }
});

// 4. Logout (Çıkış Yap)
app.post('/api/logout', (req, res) => {
  res.clearCookie('maestro_session');
  res.json({ ok: true });
});

// 5. Forgot Password (Şifremi Unuttum)
app.post('/api/forgot-password', (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    const normEmail = emailKey(email);
    const db = readDb();
    if (!db.users[normEmail]) {
      return res.json({ ok: true, message: 'If registered, reset instructions have been set.' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    db.users[normEmail].resetToken = resetToken;
    db.users[normEmail].resetExpires = Date.now() + 3600e3;
    writeDb(db);

    res.json({ ok: true, message: 'Reset token created.', debugToken: resetToken });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 6. Reset Password (Yeni Şifre Belirleme)
app.post('/api/reset-password', (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    if (!email || !token || !newPassword) return res.status(400).json({ error: 'All fields required' });

    const normEmail = emailKey(email);
    const db = readDb();
    const user = db.users[normEmail];

    if (!user || user.resetToken !== token || user.resetExpires < Date.now()) {
      return res.status(400).json({ error: 'Invalid or expired token.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(newPassword, salt, 64).toString('hex');

    user.passwordHash = `${salt}:${hash}`;
    delete user.resetToken;
    delete user.resetExpires;
    writeDb(db);

    res.json({ ok: true, message: 'Password updated successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});
app.listen(PORT_FINAL, () => {
  console.log(`Maestro server running on port ${PORT_FINAL} - Created by V. Aliyev`);
});
