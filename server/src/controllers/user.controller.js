const bcrypt = require('bcrypt');
const db = require('../config/db');
const logSecurity = require('../utils/logger');

exports.me = async (req, res) => {
  const [rows] = await db.query('SELECT id, name, email, role, created_at FROM users WHERE id=?', [req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
};

exports.updateMe = async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'name and email required' });
  try {
    await db.query('UPDATE users SET name=?, email=? WHERE id=?', [name, email, req.user.id]);
    await logSecurity(req, req.user.id, 'PROFILE_UPDATE', {});
    res.json({ message: 'Profile updated' });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email in use' });
    throw e;
  }
};

exports.changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Invalid input' });
  const [rows] = await db.query('SELECT password_hash FROM users WHERE id=?', [req.user.id]);
  if (!(await bcrypt.compare(currentPassword, rows[0].password_hash))) return res.status(401).json({ error: 'Wrong current password' });
  await db.query('UPDATE users SET password_hash=? WHERE id=?', [await bcrypt.hash(newPassword, 10), req.user.id]);
  await logSecurity(req, req.user.id, 'PASSWORD_CHANGE', {});
  res.json({ message: 'Password changed' });
};

exports.myScans = async (req, res) => {
  const page = parseInt(req.query.page || '1');
  const limit = Math.min(parseInt(req.query.limit || '10'), 50);
  const offset = (page - 1) * limit;
  const [rows] = await db.query('SELECT id, url, status_code, score, created_at FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?', [req.user.id, limit, offset]);
  res.json(rows);
};
