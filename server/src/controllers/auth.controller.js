const bcrypt = require('bcrypt');
const crypto = require('crypto');
const db = require('../config/db');
const { signAccess, signRefresh } = require('../utils/jwt');
const logSecurity = require('../utils/logger');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

async function issueTokens(req, res, user) {
  const access = signAccess(user);
  const refresh = signRefresh(user);
  const expires = new Date(Date.now() + 7 * 24 * 3600 * 1000);
  await db.query('INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?,?,?)', [user.id, sha256(refresh), expires]);
  res.cookie('refreshToken', refresh, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 });
  return access;
}

exports.register = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email, password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password min 8 chars' });
  const [rows] = await db.query('SELECT id FROM users WHERE email=?', [email]);
  if (rows.length) return res.status(409).json({ error: 'Email already exists' });
  const hash = await bcrypt.hash(password, 10);
  const [r] = await db.query('INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,\'user\')', [name, email, hash]);
  await logSecurity(req, r.insertId, 'REGISTER', { email });
  res.status(201).json({ id: r.insertId, name, email, role: 'user' });
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.query('SELECT * FROM users WHERE email=?', [email]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    await logSecurity(req, null, 'LOGIN_FAIL', { email });
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const access = await issueTokens(req, res, user);
  await logSecurity(req, user.id, 'LOGIN_SUCCESS', {});
  res.json({ accessToken: access, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
};

exports.logout = async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (token) await db.query('UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?', [sha256(token)]);
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out' });
};

exports.refresh = async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.status(401).json({ error: 'No refresh token' });
  try {
    const payload = require('jsonwebtoken').verify(token, process.env.JWT_REFRESH_SECRET);
    const [rows] = await db.query('SELECT * FROM refresh_tokens WHERE token_hash=? AND revoked=0 AND expires_at > NOW()', [sha256(token)]);
    if (!rows.length) return res.status(401).json({ error: 'Revoked or expired' });
    const [u] = await db.query('SELECT * FROM users WHERE id=?', [payload.id]);
    if (!u.length) return res.status(401).json({ error: 'User not found' });
    await db.query('UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?', [sha256(token)]);
    const access = await issueTokens(req, res, u[0]);
    res.json({ accessToken: access });
  } catch { return res.status(401).json({ error: 'Invalid refresh token' }); }
};

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  const [rows] = await db.query('SELECT id FROM users WHERE email=?', [email]);
  if (!rows.length) return res.json({ message: 'If the email exists, a reset token was sent' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 3600 * 1000);
  await db.query('UPDATE users SET reset_token=?, reset_token_expires=? WHERE id=?', [sha256(token), expires, rows[0].id]);
  await logSecurity(req, rows[0].id, 'PASSWORD_RESET_REQUEST', {});
  res.json({ message: 'Reset token created (dev mode)', resetToken: token });
};

exports.resetPassword = async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password || password.length < 8) return res.status(400).json({ error: 'token and password(min 8) required' });
  const [rows] = await db.query('SELECT id FROM users WHERE reset_token=? AND reset_token_expires > NOW()', [sha256(token)]);
  if (!rows.length) return res.status(400).json({ error: 'Invalid or expired token' });
  const hash = await bcrypt.hash(password, 10);
  await db.query('UPDATE users SET password_hash=?, reset_token=NULL, reset_token_expires=NULL WHERE id=?', [hash, rows[0].id]);
  await logSecurity(req, rows[0].id, 'PASSWORD_RESET', {});
  res.json({ message: 'Password updated' });
};
