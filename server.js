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
app.listen(PORT_FINAL, () => {
  console.log(`Maestro server running on port ${PORT_FINAL} - Created by V. Aliyev`);
});
