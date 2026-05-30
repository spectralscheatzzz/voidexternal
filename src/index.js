const exp = require('express');
const crypto = require('crypto');
const limit = require('express-rate-limit');
const pool = require('./db')
require('dotenv').config()

const app = exp()
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET');
  next();
});
const auth_secret = process.env.GEN_AUTH_SECRET;

function genkey(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = '';
  const bytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    key += chars[bytes[i] % chars.length];
  }
  return key;
}

const limiter = limit({windowMs: 60 * 1000, max: 30, message: { valid: false, error: 'Too many requests' }})
app.use('/checkkey', limiter)
app.get('/genkey', async (req, res) => {
  const { auth, days } = req.query;
  if (!auth || auth !== auth_secret) {
    return res.status(403).json({ error: 'unauthorized' });
  }
  const daysnum = parseInt(days);
  if (!daysnum || daysnum < 1 || daysnum > 365) {
    return res.status(400).json({ error: 'days have to be between 1 and 365' });
  }
  const key = genkey(32);
  const expiration = new Date(Date.now() + daysnum * 86400000);
  await pool.query(
    'INSERT INTO keys (key, expires_at) VALUES ($1, $2)',
    [key, expiration]
  );
  return res.json({ key, expires_at: expiration});
})

app.get('/checkkey', async (req, res) => {
  const { key, hwid } = req.query;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (!key || !hwid) {
    return res.status(400).json({ valid: false, error: "Missing key or hwid" });
  }
  const { rows } = await pool.query('SELECT * FROM keys WHERE key = $1', [key]);
  if (rows.length === 0) {
    await logAttempt(key, hwid, ip, 'not_found');
    return res.json({ valid: false, error: 'Key not found' });
  }
  const record = rows[0];
  if (!record.is_active) {
    await logAttempt(key, hwid, ip, 'revoked');
    return res.json({ valid: false, error: 'Key revoked' });
  }
  if (new Date() > new Date(record.expires_at)) {
    await logAttempt(key, hwid, ip, 'expired');
    return res.json({ valid: false, error: 'Key expired' });
  }
  if (record.hwid === null) {
    await pool.query('UPDATE keys SET hwid = $1, redeemed_at = NOW() WHERE key = $2', [hwid, key]);
    await logAttempt(key, hwid, ip, 'activated');
    return res.json({ valid: true, message: 'Key activated', expires_at: record.expires_at });
  }
  if (record.hwid !== hwid) {
    await logAttempt(key, hwid, ip, 'hwid_mismatch');
    return res.json({ valid: false, error: 'hwid mismatch' });
  }
  await logAttempt(key, hwid, ip, 'valid');
  return res.json({ valid: true, expires_at: record.expires_at });
});

app.get('/resetkey', async (req, res) => {
  const { auth, key } = req.query;
  if (!auth || auth !== auth_secret) {
    return res.status(403).json({ error: 'unauthorized' });
  }
  const result = await pool.query('UPDATE keys SET hwid = NULL, redeemed_at = NULL WHERE key = $1', [key]);
  if (result.rowCount === 0) {
    return res.status(404).json({ error: 'Key not found' });
  }
  return res.json({ success: true, message: 'hwid reset' });
});

app.get('/revokekey', async (req, res) => {
  const { auth, key } = req.query;
  if (!auth || auth !== auth_secret) {
    return res.status(403).json({ error: 'unauthorized' });
  }
  const result = await pool.query('UPDATE keys SET is_active = FALSE WHERE key = $1', [key]);
  if (result.rowCount === 0) {
    return res.status(404).json({ error: 'Key not found' });
  }
  return res.json({ success: true, message: 'Key revoked' });
});

async function logAttempt(key, hwid, ip, result) {
  await pool.query(
    'INSERT INTO key_logs (key, hwid, ip, result) VALUES ($1, $2, $3, $4)',
    [key, hwid, ip, result]
  );
}

app.listen(process.env.PORT || 3000, () => {
  console.log('Key system working');
});
