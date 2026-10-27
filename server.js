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
  PORT = 3000, JWT_SECRET, OPENAI_API_KEY,
  FREE_CREDITS = '3'
} = process.env;

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// Health Check
app.get('/api/health', (_req, res) => res.json({ ok: true, ai: !!OPENAI_API_KEY, author: 'V. Aliyev' }));

// Anti-abuse & Email normalization
function emailKey(em) {
  let [local, domain] = String(em || '').split('@');
  if (!local || !domain) return em;
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (domain === 'gmail.com') local = local.replace(/\./g, '').split('+')[0];
  return `${local}@${domain}`;
}

const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org', 'yopmail.com', 'trashmail.com']);
const signupLimit = rateLimit({ windowMs: 24 * 3600e3, max: 10, message: { error: 'Too many sign-ups. Try again later.' } });
const authLimit = rateLimit({ windowMs: 15 * 60e3, max: 30 });
const genLimit = rateLimit({ windowMs: 60e3, max: 10, message: { error: 'Too many generations. Please wait a minute.' } });

// Meta Info
app.get('/api/meta', (_req, res) => {
  res.json({
    appName: 'Maestro AI',
    domain: 'maestroai.design',
    supportEmail: 'support@maestroai.design',
    author: 'Created by V. Aliyev'
  });
});

// Database Helpers
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

// 1. Signup
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

// 2. Login
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

// 3. Current User Check
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

// 4. Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('maestro_session');
  res.json({ ok: true });
});

// 5. Forgot Password
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

// 6. Generate Endpoint (Şəkil dizayn etmək üçün - 404 xətası verməməsi üçün əlavə olundu)
app.post('/api/generate', genLimit, (req, res) => {
  try {
    const sessionEmail = req.cookies.maestro_session;
    const db = readDb();
    
    // İstifadəçi daxil olubsa kreditini yoxlayaq
    if (sessionEmail && db.users[sessionEmail]) {
      if (db.users[sessionEmail].credits <= 0) {
        return res.status(400).json({ error: 'Yetersiz kredit. Zəhmət olmasa kredit əldə edin.' });
      }
      db.users[sessionEmail].credits -= 1;
      writeDb(db);
    }

    // Əgər OpenAI açarı varsa burada generasiya edə bilər, yoxdursa test üçün uğurlu cavab qaytarır
    // Öz real generasiya kodunu buraya əlavə edə bilərsən
    res.json({ 
      ok: true, 
      imageUrl: 'https://images.unsplash.com/photo-1618221195710-dd6b41faaea6?q=80&w=1000&auto=format&fit=crop',
      message: 'Dizayn uğurla yaradıldı!' 
    });
  } catch (err) {
    res.status(500).json({ error: 'Generasiya zamanı xəta baş verdi.' });
  }
});

// Catch-all route to prevent 404 on frontend routing
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
// Paddle Webhook (Ödəniş uğurlu olduqda kredit artırma)
app.post('/api/webhook/paddle', express.json(), (req, res) => {
  try {
    const event = req.body;
    if (event && event.event_type === 'transaction.completed') {
      const transaction = event.data;
      const customerEmail = transaction.customer && transaction.customer.email;
      if (customerEmail) {
        const normEmail = emailKey(customerEmail);
        const db = readDb();
        if (db.users[normEmail]) {
          db.users[normEmail].credits = (db.users[normEmail].credits || 0) + 10;
          writeDb(db);
        }
      }
    }
    res.status(200).json({ received: true });
  } catch (err) {
    res.status(500).json({ received: false });
  }
});
const PORT_FINAL = process.env.PORT || 3000;
app.listen(PORT_FINAL, () => {
  console.log(`Maestro server running on port ${PORT_FINAL} - Created by V. Aliyev`);
});
